// Package dataplane is the pg-proxy worker's gateway-facing data path: accept a
// mesh mTLS connection, redeem the session, and proxy pgwire to the target.
package dataplane

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"connectrpc.com/connect"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/control"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/mesh"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/pgproxy"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/record"
)

// sessionSetupTimeout bounds PrepareSession + DialTarget so a hung warden RPC or a
// stalled target handshake cannot wedge the handler goroutine indefinitely.
const sessionSetupTimeout = 10 * time.Second

// errNoAnchors means PrepareSession returned no applicable trust anchor, so there
// is nothing to authenticate the target against — the session fails closed.
var errNoAnchors = errors.New("no current trust anchors for asset")

// handleConn runs one gateway connection end-to-end: CONNECT → pgwire startup →
// PrepareSession redeem → validate role → dial target → match identity →
// IssueSessionCredential → complete auth → splice.
// raw is the accepted (already TLS-terminated) connection.
func handleConn(ctx context.Context, raw net.Conn, workerID string, client dataplanev1connect.DataplaneServiceClient, reg *control.Registry, ended chan<- control.SessionEnd, uploader record.Uploader) {
	defer func() { _ = raw.Close() }()

	token, tunnel, err := mesh.ReadConnect(raw)
	if err != nil {
		slog.Warn("bad CONNECT", "err", err)
		return
	}
	if err := mesh.WriteEstablished(raw); err != nil {
		return
	}

	be, startup, err := pgproxy.ReadStartup(tunnel)
	if err != nil {
		slog.Warn("pg startup", "err", err)
		return
	}

	setupCtx, cancelSetup := context.WithTimeout(ctx, sessionSetupTimeout)
	defer cancelSetup()

	// Phase 1: PrepareSession — redeem the token and get the endpoint + the asset's
	// current active trust anchors, but NO credential. Warden releases a credential
	// only after we authenticate the target against these anchors (phase 2).
	prep, err := client.PrepareSession(setupCtx, connect.NewRequest(&dataplanev1.PrepareSessionRequest{
		SessionToken: token,
		WorkerId:     workerID,
		Login:        startup.User, // warden authorizes the token's bound role and echoes it as resp.Login
	}))
	if err != nil {
		slog.Warn("prepare session", "err", err)
		pgproxy.RejectUser(be, "access denied")
		return
	}
	p := prep.Msg
	// The client must connect as exactly the role warden authorized.
	if startup.User != p.GetLogin() {
		pgproxy.RejectUser(be, "must connect as role "+p.GetLogin())
		return
	}

	// Fail closed: warden requires recording but this worker has no upload target.
	if p.GetRecordingRequired() && uploader == nil {
		pgproxy.RejectUser(be, "recording unavailable")
		return
	}

	// Credential-free observe of the REAL target, then match its identity against the
	// prepared anchors locally — all before any credential exists. This is a separate
	// TLS handshake from the credentialed pgconn dial below (pgconn drives its own TLS
	// with the credential up front), so a verified session costs two handshakes to the
	// target: one to authenticate identity here, one credentialed after issuance.
	anchorID, observedFP, verr := observeAndMatch(setupCtx, p)
	if verr != nil {
		slog.Warn("target identity verification failed", "err", verr, "asset_target", p.GetTargetAddress())
		pgproxy.RejectUser(be, "target identity not verified")
		return
	}

	// Phase 2: IssueSessionCredential — warden re-confirms the matched anchor is
	// current+active for the asset revision, then releases the credential.
	issued, err := client.IssueSessionCredential(setupCtx, connect.NewRequest(&dataplanev1.IssueSessionCredentialRequest{
		SessionId:           p.GetSessionId(),
		WorkerId:            workerID,
		EndpointRevision:    p.GetEndpointRevision(),
		MatchedAnchorId:     anchorID,
		ObservedFingerprint: observedFP,
	}))
	if err != nil {
		slog.Warn("issue session credential", "err", err)
		pgproxy.RejectUser(be, "access denied")
		return
	}
	r := issued.Msg

	db := startup.Database
	if db == "" {
		db = p.GetDefaultDatabase()
	}
	// Re-authenticate the identical approved identity on the credentialed handshake.
	matched := matchedAnchor(p, anchorID)
	verifiedTLS := pgproxy.VerifiedTLSConfig(pgproxy.HostOf(p.GetTargetAddress()), matched, time.Now)
	target, err := pgproxy.DialTarget(setupCtx, p.GetTargetAddress(), db, p.GetLogin(), credOf(r), verifiedTLS)
	if err != nil {
		slog.Warn("dial target", "err", err)
		pgproxy.RejectUser(be, "target unavailable")
		return
	}

	if err := pgproxy.CompleteAuth(be); err != nil {
		_ = target.Close()
		return
	}

	sid := p.GetSessionId()

	var rec *record.Recorder
	start := time.Now()
	if p.GetRecordingRequired() {
		rec = record.New(uploader, p.GetRecordingObjectKey(), record.Header{
			V: 1, Kind: "pg", SessionID: sid, Role: p.GetLogin(),
			Database: db, StartedAtMS: start.UnixMilli(),
		})
	}

	// Teardown from the control loop fires cancel; natural EOF ends Splice via its
	// own goroutines. Only Teardown ever closes cancel (Registry fires each entry's
	// func at most once, then deletes it), so there is no double-close.
	cancel := make(chan struct{})
	reg.Add(sid, func() { close(cancel) })
	defer reg.Remove(sid)

	reason := pgproxy.Splice(be, tunnel, target, cancel, rec, start)

	end := control.SessionEnd{SessionID: sid, Reason: reason}
	if rec != nil {
		// Upload detached from cancellation: ctx may already be cancelled by teardown.
		upCtx, upCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		rep := rec.Finish(upCtx, time.Now().UnixMilli())
		upCancel()
		end.Recording = &dataplanev1.RecordingInfo{
			ObjectKey:       rep.ObjectKey,
			SizeBytes:       rep.SizeBytes,
			Sha256:          rep.SHA256Hex,
			StartedAtUnixMs: rep.StartedAtMS,
			EndedAtUnixMs:   rep.EndedAtMS,
			Status:          rep.Status,
			GrantId:         p.GetGrantId(),
		}
	}
	select {
	case ended <- end:
	default:
	}
}

// credOf maps the IssueSessionCredential response's credential oneof to a
// TargetCredential.
func credOf(r *dataplanev1.IssueSessionCredentialResponse) pgproxy.TargetCredential {
	if c := r.GetX509Certificate(); len(c) > 0 {
		return pgproxy.TargetCredential{X509CertPEM: c, X509KeyPEM: r.GetX509PrivateKey()}
	}
	return pgproxy.TargetCredential{Password: r.GetPgPassword()}
}

// observeAndMatch runs the credential-free TLS observe against the real target and
// matches its identity against the prepared trust anchors, returning the matched
// anchor id and the observed leaf fingerprint. It fails closed: any observe error,
// no anchors, or no anchor match returns an error and NO credential is requested.
func observeAndMatch(ctx context.Context, p *dataplanev1.PrepareSessionResponse) (anchorID, observedFP string, err error) {
	host, port, err := pgproxy.SplitTargetAddr(p.GetTargetAddress())
	if err != nil {
		return "", "", err
	}
	anchors := sessionAnchors(p)
	if len(anchors) == 0 {
		return "", "", errNoAnchors
	}
	obs, err := pgproxy.ObserveTarget(ctx, host, port, host, pgproxy.DefaultProbeLimits())
	if err != nil {
		return "", "", err
	}
	return pgproxy.MatchIdentity(obs, anchors, time.Now())
}

// sessionAnchors maps the prepared TLS trust anchors into the worker's match form,
// dropping non-TLS kinds (a pg asset only carries tls_leaf / tls_ca).
func sessionAnchors(p *dataplanev1.PrepareSessionResponse) []pgproxy.SessionAnchor {
	out := make([]pgproxy.SessionAnchor, 0, len(p.GetTrustAnchors()))
	for _, a := range p.GetTrustAnchors() {
		if a.GetKind() != "tls_leaf" && a.GetKind() != "tls_ca" {
			continue
		}
		out = append(out, pgproxy.SessionAnchor{
			ID:                  a.GetId(),
			Kind:                a.GetKind(),
			Fingerprint:         a.GetSha256Fingerprint(),
			RequiredDNSNames:    a.GetRequiredDnsNames(),
			RequiredIPAddresses: a.GetRequiredIpAddresses(),
			PublicMaterial:      a.GetPublicMaterial(),
		})
	}
	return out
}

// matchedAnchor finds the prepared anchor with id, for the credentialed re-verify.
func matchedAnchor(p *dataplanev1.PrepareSessionResponse, id string) pgproxy.SessionAnchor {
	for _, a := range sessionAnchors(p) {
		if a.ID == id {
			return a
		}
	}
	return pgproxy.SessionAnchor{}
}
