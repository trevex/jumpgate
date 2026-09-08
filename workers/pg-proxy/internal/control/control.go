package control

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/pgproxy"
)

const (
	heartbeatInterval = 10 * time.Second
	reconnectBackoff  = 2 * time.Second
)

// RunConfig configures the WorkerStream registration.
type RunConfig struct {
	WorkerID         string
	DataplaneAddress string
	Capacity         int32
	Protocols        []string
}

// SessionEnd is a finished-session report pushed by the data-plane path for the
// control loop to forward to warden as a SessionEnded frame. Recording is non-nil
// when the session was recorded (or a recording was attempted).
type SessionEnd struct {
	SessionID string
	Reason    string
	Recording *dataplanev1.RecordingInfo
}

// Run maintains the WorkerStream lifeline: registers, heartbeats, forwards
// SessionEnd reports from `ended`, and dispatches inbound Teardown to reg,
// reconnecting with backoff until ctx ends.
func Run(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *Registry, cfg RunConfig, ended <-chan SessionEnd) error {
	for {
		if err := connectAndRun(ctx, client, reg, cfg, ended); err != nil && ctx.Err() == nil {
			slog.Warn("worker stream dropped; reconnecting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reconnectBackoff):
		}
	}
}

func connectAndRun(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *Registry, cfg RunConfig, ended <-chan SessionEnd) error {
	stream := client.WorkerStream(ctx)
	defer func() { _ = stream.CloseRequest() }()
	defer func() { _ = stream.CloseResponse() }()

	if err := stream.Send(&dataplanev1.WorkerMessage{
		Msg: &dataplanev1.WorkerMessage_Register{Register: &dataplanev1.Register{
			WorkerId:         cfg.WorkerID,
			Protocols:        cfg.Protocols,
			Capacity:         cfg.Capacity,
			LiveSessionIds:   reg.LiveIDs(),
			DataplaneAddress: cfg.DataplaneAddress,
		}},
	}); err != nil {
		return err
	}

	// The control loop is the single writer of the stream; the receive path runs in
	// its own goroutine and reports errors back over recvErr. Probe assignments are
	// funnelled to the control loop (the sole writer) as unsupported results.
	recvErr := make(chan error, 1)
	// Comfortably above warden's per-worker probe ceiling (MaxPerWorker, default 2),
	// so the non-blocking-send drop path below is effectively unreachable; 8 is a
	// headroom constant, not a tuned value.
	probeResults := make(chan *dataplanev1.ProbeResult, 8)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			if td := msg.GetTeardown(); td != nil {
				reg.Teardown(td.GetSessionId())
			}
			if pa := msg.GetProbeAssignment(); pa != nil {
				// Run the credential-free TLS identity probe and reply with the observed
				// evidence (or a categorized failure). Dispatched in its own goroutine so
				// the receive loop keeps draining teardown/heartbeat frames while the
				// probe's deadlines run. Non-blocking send; a full buffer lets the lease
				// expire.
				go func(pa *dataplanev1.ProbeAssignment) {
					pr := runPostgresProbe(ctx, pa)
					select {
					case probeResults <- pr:
					default:
						slog.Warn("probe result buffer full; dropping reply", "job_id", pa.GetJobId())
					}
				}(pa)
			}
		}
	}()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ticker.C:
			if err := stream.Send(&dataplanev1.WorkerMessage{
				Msg: &dataplanev1.WorkerMessage_Heartbeat{Heartbeat: &dataplanev1.Heartbeat{}},
			}); err != nil {
				return err
			}
		case se := <-ended:
			if err := stream.Send(&dataplanev1.WorkerMessage{
				Msg: &dataplanev1.WorkerMessage_SessionEnded{SessionEnded: &dataplanev1.SessionEnded{
					SessionId: se.SessionID,
					Reason:    se.Reason,
					Recording: se.Recording,
				}},
			}); err != nil {
				return err
			}
		case pr := <-probeResults:
			if err := stream.Send(&dataplanev1.WorkerMessage{
				Msg: &dataplanev1.WorkerMessage_ProbeResult{ProbeResult: pr},
			}); err != nil {
				return err
			}
		}
	}
}

// runPostgresProbe executes the credential-free TLS identity probe described by pa
// and maps the outcome to exactly one terminal ProbeResult: a Succeeded result
// carrying the observed certificate chain as evidence, or a Failed result with a
// category + detail. It never sends the pg startup packet or any credential.
func runPostgresProbe(ctx context.Context, pa *dataplanev1.ProbeAssignment) *dataplanev1.ProbeResult {
	base := &dataplanev1.ProbeResult{
		JobId:            pa.GetJobId(),
		AssetId:          pa.GetAssetId(),
		EndpointRevision: pa.GetEndpointRevision(),
		LeaseToken:       pa.GetLeaseToken(),
		Protocol:         pa.GetProtocol(),
		ObservedAtUnixMs: time.Now().UnixMilli(),
	}
	ep := pa.GetPostgres()
	if ep == nil {
		base.Outcome = dataplanev1.ProbeOutcome_PROBE_OUTCOME_FAILED
		base.FailureCategory = dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_MALFORMED_IDENTITY
		base.FailureDetail = "probe assignment is not a postgres endpoint"
		return base
	}
	obs, err := pgproxy.ObserveTarget(ctx, ep.GetHost(), ep.GetPort(), ep.GetServerName(), probeLimits(pa.GetLimits()))
	if err != nil {
		base.Outcome = dataplanev1.ProbeOutcome_PROBE_OUTCOME_FAILED
		base.FailureCategory = probeFailureCategory(err)
		base.FailureDetail = err.Error()
		return base
	}
	base.Outcome = dataplanev1.ProbeOutcome_PROBE_OUTCOME_SUCCEEDED
	base.ResolvedAddresses = obs.ResolvedAddresses
	base.Evidence = chainEvidence(obs.Chain)
	base.ProtocolMetadata = &dataplanev1.ProbeResult_Tls{Tls: &dataplanev1.ProbeTLSMetadata{
		Version:     obs.TLSVersion,
		CipherSuite: obs.CipherSuite,
		ServerName:  obs.ServerName,
		Alpn:        obs.ALPN,
	}}
	return base
}

// chainEvidence renders an observed TLS chain (leaf first) into ProbeEvidence rows:
// the leaf is TLS_LEAF, a trailing self-signed CA is TLS_PRESENTED_ROOT, and the
// rest are TLS_INTERMEDIATE. A root absent from the presented chain is never invented.
func chainEvidence(chain []*x509.Certificate) []*dataplanev1.ProbeEvidence {
	out := make([]*dataplanev1.ProbeEvidence, 0, len(chain))
	for i, c := range chain {
		kind := dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_INTERMEDIATE
		switch {
		case i == 0:
			kind = dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_LEAF
		case i == len(chain)-1 && isSelfSigned(c):
			kind = dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_PRESENTED_ROOT
		}
		ev := &dataplanev1.ProbeEvidence{
			Kind:               kind,
			Algorithm:          c.PublicKeyAlgorithm.String(),
			Sha256Fingerprint:  pgproxy.FingerprintDER(c.Raw),
			PublicMaterial:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
			CertificateSubject: c.Subject.String(),
			CertificateIssuer:  c.Issuer.String(),
			DnsNames:           c.DNSNames,
			IpAddresses:        ipStrings(c.IPAddresses),
			SerialNumber:       c.SerialNumber.String(),
			ValidFromUnixMs:    c.NotBefore.UnixMilli(),
			ValidUntilUnixMs:   c.NotAfter.UnixMilli(),
		}
		if i+1 < len(chain) {
			ev.IssuerSha256Fingerprint = pgproxy.FingerprintDER(chain[i+1].Raw)
		}
		out = append(out, ev)
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// probeLimits maps warden's assignment limits into the observe's bounds, applying
// conservative defaults for any unset field.
func probeLimits(l *dataplanev1.ProbeLimits) pgproxy.ProbeLimits {
	lim := pgproxy.DefaultProbeLimits()
	if l == nil {
		return lim
	}
	if l.GetDnsTimeoutMs() > 0 {
		lim.DNSTimeout = time.Duration(l.GetDnsTimeoutMs()) * time.Millisecond
	}
	if l.GetConnectTimeoutMs() > 0 {
		lim.ConnectTimeout = time.Duration(l.GetConnectTimeoutMs()) * time.Millisecond
	}
	if l.GetHandshakeTimeoutMs() > 0 {
		lim.HandshakeTimeout = time.Duration(l.GetHandshakeTimeoutMs()) * time.Millisecond
	}
	if l.GetTotalTimeoutMs() > 0 {
		lim.TotalTimeout = time.Duration(l.GetTotalTimeoutMs()) * time.Millisecond
	}
	if l.GetMaxChainCertificates() > 0 {
		lim.MaxChainCertificates = int(l.GetMaxChainCertificates())
	}
	if l.GetMaxCertificateBytes() > 0 {
		lim.MaxCertificateBytes = int(l.GetMaxCertificateBytes())
	}
	return lim
}

// probeFailureCategory maps a probe observe error to its wire failure category.
func probeFailureCategory(err error) dataplanev1.ProbeFailureCategory {
	var pe *pgproxy.ProbeError
	if !errors.As(err, &pe) {
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_PROTOCOL_MISMATCH
	}
	switch pe.Kind {
	case pgproxy.ProbeErrDNS:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_DNS_RESOLUTION_FAILED
	case pgproxy.ProbeErrConnectionRefused:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CONNECTION_REFUSED
	case pgproxy.ProbeErrConnectionTimeout:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CONNECTION_TIMEOUT
	case pgproxy.ProbeErrInsecureDowngrade:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_INSECURE_DOWNGRADE
	case pgproxy.ProbeErrMalformedIdentity:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_MALFORMED_IDENTITY
	case pgproxy.ProbeErrIdentityTooLarge:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_IDENTITY_TOO_LARGE
	default:
		return dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_PROTOCOL_MISMATCH
	}
}
