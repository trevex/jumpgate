// Package dataplane is the pg-proxy worker's gateway-facing data path: accept a
// mesh mTLS connection, redeem the session, and proxy pgwire to the target.
package dataplane

import (
	"context"
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

// sessionSetupTimeout bounds SetupSession + DialTarget so a hung warden RPC or a
// stalled target handshake cannot wedge the handler goroutine indefinitely.
const sessionSetupTimeout = 10 * time.Second

// handleConn runs one gateway connection end-to-end: CONNECT → pgwire startup →
// SetupSession redeem → validate role → complete auth → dial target → splice.
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

	resp, err := client.SetupSession(setupCtx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken: token,
		WorkerId:     workerID,
		Login:        startup.User, // warden authorizes the token's bound role and echoes it as resp.Login
	}))
	if err != nil {
		slog.Warn("setup session", "err", err)
		pgproxy.RejectUser(be, "access denied")
		return
	}
	r := resp.Msg
	// The client must connect as exactly the role warden authorized.
	if startup.User != r.GetLogin() {
		pgproxy.RejectUser(be, "must connect as role "+r.GetLogin())
		return
	}

	// Fail closed: warden requires recording but this worker has no upload target.
	if r.GetRecordingRequired() && uploader == nil {
		pgproxy.RejectUser(be, "recording unavailable")
		return
	}

	db := startup.Database
	if db == "" {
		db = r.GetDefaultDatabase()
	}
	target, err := pgproxy.DialTarget(setupCtx, r.GetTargetAddress(), db, r.GetLogin(), credOf(r), r.GetTargetServerCa())
	if err != nil {
		slog.Warn("dial target", "err", err)
		pgproxy.RejectUser(be, "target unavailable")
		return
	}

	if err := pgproxy.CompleteAuth(be); err != nil {
		_ = target.Close()
		return
	}

	sid := r.GetSessionId()

	var rec *record.Recorder
	start := time.Now()
	if r.GetRecordingRequired() {
		rec = record.New(uploader, r.GetRecordingObjectKey(), record.Header{
			V: 1, Kind: "pg", SessionID: sid, Role: r.GetLogin(),
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
			GrantId:         r.GetGrantId(),
		}
	}
	select {
	case ended <- end:
	default:
	}
}

// credOf maps the SetupSession response's credential oneof to a TargetCredential.
func credOf(r *dataplanev1.SetupSessionResponse) pgproxy.TargetCredential {
	if c := r.GetX509Certificate(); len(c) > 0 {
		return pgproxy.TargetCredential{X509CertPEM: c, X509KeyPEM: r.GetX509PrivateKey()}
	}
	return pgproxy.TargetCredential{Password: r.GetPgPassword()}
}
