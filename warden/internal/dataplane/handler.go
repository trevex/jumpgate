package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// workerIdentity returns the authoritative worker id from the request's mesh
// identity, enforcing that the caller presented a `worker`- or `broker`-role mesh
// cert whose SAN id equals claimedID. Enforcement is UNCONDITIONAL: no mesh
// identity in ctx (illegitimate on the mesh listener, where mTLS guarantees
// identity) or a claim that differs from the cert → PermissionDenied. The k8s
// broker registers on this same worker lifeline as role `broker`.
func workerIdentity(ctx context.Context, claimedID string) (string, error) {
	id, ok := mesh.IdentityFromContext(ctx)
	if !ok || (id.Role != "worker" && id.Role != "broker") {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("worker or broker mesh identity required"))
	}
	if claimedID != id.ID {
		return "", connect.NewError(connect.CodePermissionDenied, fmt.Errorf("worker_id %q does not match cert identity %q", claimedID, id.ID))
	}
	return id.ID, nil
}

// Handler implements dataplanev1connect.DataplaneServiceHandler: the
// worker lifeline stream (register/heartbeat/session-ended + teardown push) and
// the unary session-setup admission RPC.
type Handler struct {
	setup      *SetupService
	registry   *Registry
	pool       *pgxpool.Pool
	terminator *Terminator
}

// NewHandler constructs the data-plane RPC implementation.
func NewHandler(setup *SetupService, registry *Registry, pool *pgxpool.Pool, terminator *Terminator) *Handler {
	return &Handler{setup: setup, registry: registry, pool: pool, terminator: terminator}
}

// SetupSession redeems a session token: it re-checks authorization, records the
// live session, and issues a JIT SSH certificate. Domain sentinels are mapped to
// Connect codes here; the domain layer stays transport-agnostic.
func (s *Handler) SetupSession(ctx context.Context, req *connect.Request[dataplanev1.SetupSessionRequest]) (*connect.Response[dataplanev1.SetupSessionResponse], error) {
	// Derive the authoritative worker id from the mTLS cert SAN; the request must
	// not claim a different worker than its certificate (else PermissionDenied).
	workerID, err := workerIdentity(ctx, req.Msg.WorkerId)
	if err != nil {
		return nil, err
	}
	out, err := s.setup.Setup(ctx, req.Msg.SessionToken, workerID, req.Msg.Login, req.Msg.ClientSshPublicKey, req.Msg.TargetPublicKey)
	switch {
	case errors.Is(err, ErrBadToken), errors.Is(err, ErrKeyMismatch):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, ErrNotAuthorized):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, ErrReplay):
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, ErrNoTarget):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &dataplanev1.SetupSessionResponse{
		TargetAddress:      out.TargetAddress,
		SessionId:          out.SessionID,
		RecordingRequired:  out.RecordingRequired,
		RecordingObjectKey: out.RecordingObjectKey,
		TargetHostKey:      out.TargetHostKey,
		TargetServerCa:     out.TargetServerCA,
		DefaultDatabase:    out.DefaultDatabase,
		GrantId:            out.GrantID,
		Login:              out.Login,
	}
	switch out.CredentialKind {
	case "ssh-cert":
		resp.Credential = &dataplanev1.SetupSessionResponse_SshCertificate{SshCertificate: out.SSHCertificate}
	case "ssh-password":
		resp.Credential = &dataplanev1.SetupSessionResponse_Password{Password: out.Password}
	case "ssh-key":
		resp.Credential = &dataplanev1.SetupSessionResponse_PrivateKey{PrivateKey: out.PrivateKey}
	case "x509":
		resp.Credential = &dataplanev1.SetupSessionResponse_X509Certificate{X509Certificate: out.X509Certificate}
		resp.X509PrivateKey = out.X509PrivateKey
	case "pg-password":
		resp.Credential = &dataplanev1.SetupSessionResponse_PgPassword{PgPassword: out.Password}
	default:
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("unexpected credential kind %q", out.CredentialKind))
	}
	return connect.NewResponse(resp), nil
}

// WorkerStream is the worker's lifeline. The worker sends Register (first frame),
// then Heartbeat and SessionEnded frames; warden acks the registration and pushes
// Teardown frames toward the worker's teardown sink. The stream stays open for the
// worker's lifetime.
//
// Concurrency: a recv goroutine drains inbound frames; the main loop selects on
// the teardown sink and ctx. The recv goroutine exits when Receive returns (client
// half-close → io.EOF, or ctx cancel closes the stream), so it does not leak once
// the handler returns.
func (s *Handler) WorkerStream(ctx context.Context, stream *connect.BidiStream[dataplanev1.WorkerMessage, dataplanev1.ServerMessage]) error {
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil || reg.WorkerId == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first frame must be Register with worker_id"))
	}
	// The registered worker_id must equal the mTLS cert identity (cert authoritative).
	workerID, err := workerIdentity(ctx, reg.WorkerId)
	if err != nil {
		return err
	}

	sink := make(chan Signal, 64)
	s.registry.Add(workerID, sink)
	defer s.registry.Remove(workerID, sink)

	s.registry.SetWorkerMeta(workerID, WorkerMeta{
		Protocol: firstProtocolOr(reg.Protocols, "ssh"),
		Address:  reg.DataplaneAddress,
		Capacity: reg.Capacity,
	})
	defer s.registry.ClearWorkerMeta(workerID)
	defer s.registry.ClearTunnels(workerID)

	if err := sqlc.New(s.pool).UpsertWorkerPresence(ctx, workerID); err != nil {
		slog.Error("worker presence upsert failed", "worker_id", workerID, "err", err)
	}

	if err := stream.Send(&dataplanev1.ServerMessage{Msg: &dataplanev1.ServerMessage_Ack{Ack: &dataplanev1.RegisterAck{}}}); err != nil {
		return err
	}

	// Reconnect re-sync: reconcile DB-recorded sessions against what the worker reports.
	if err := s.reconcileOnRegister(ctx, workerID, reg.LiveSessionIds); err != nil {
		slog.Error("reconcile on register failed", "worker_id", workerID, "err", err)
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			if se := msg.GetSessionEnded(); se != nil {
				// Persist the recording report BEFORE marking the session ended: the
				// parties lookup reads live_sessions, which handleSessionEnded deletes.
				if rec := se.GetRecording(); rec != nil {
					if err := s.persistRecording(ctx, se.SessionId, rec); err != nil {
						slog.Error("session recording persist failed", "session_id", se.SessionId, "err", err)
					}
				}
				if err := s.handleSessionEnded(ctx, se.SessionId, se.Reason); err != nil {
					slog.Error("session ended handling failed", "session_id", se.SessionId, "err", err)
				}
			}
			if msg.GetHeartbeat() != nil {
				if err := sqlc.New(s.pool).UpsertWorkerPresence(ctx, workerID); err != nil {
					slog.Error("worker presence upsert failed", "worker_id", workerID, "err", err)
				}
			}
			if adv := msg.GetAdvertiseTunnels(); adv != nil {
				s.registry.SetTunnels(workerID, adv.GetAssetIds())
			}
			// Register(after first): no-op.
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case sig := <-sink:
			if err := stream.Send(&dataplanev1.ServerMessage{Msg: &dataplanev1.ServerMessage_Teardown{
				Teardown: &dataplanev1.Teardown{SessionId: sig.SessionID, Reason: sig.Reason},
			}}); err != nil {
				return err
			}
		}
	}
}

// firstProtocolOr returns the first protocol in ps, or def if ps is empty.
func firstProtocolOr(ps []string, def string) string {
	if len(ps) > 0 && ps[0] != "" {
		return ps[0]
	}
	return def
}

// reconcileOnRegister reconciles a (re)connecting worker's DB-recorded live sessions
// against the set it reports still having. Sessions the worker dropped are marked
// ended; sessions it retains are re-evaluated and torn down if they lost
// authorization while the stream was down. Best-effort per session (errors logged).
func (s *Handler) reconcileOnRegister(ctx context.Context, workerID string, workerLiveIDs []string) error {
	have := make(map[string]bool, len(workerLiveIDs))
	for _, id := range workerLiveIDs {
		have[id] = true
	}
	rows, err := sqlc.New(s.pool).ListLiveSessionsByWorker(ctx, workerID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !have[row.ID.String()] {
			if err := s.terminator.MarkEnded(ctx, row.ID, "worker reconnected without session"); err != nil {
				slog.Error("reconcile mark-ended failed", "session_id", row.ID, "err", err)
			}
			continue
		}
		if err := s.terminator.Reevaluate(ctx, row.UserID, row.AssetID); err != nil {
			slog.Error("reconcile reevaluate failed", "session_id", row.ID, "err", err)
		}
	}
	return nil
}

// recordingFormat maps a session protocol to its recording container format.
func recordingFormat(protocol string) string {
	switch protocol {
	case "postgres":
		return "pgwire-timeline-v1"
	case "kubernetes":
		return "k8s-audit-v1"
	default:
		return "asciicast-v2" // ssh / legacy
	}
}

// persistRecording records a worker's recording report into session_recordings and
// audits it, in a single transaction. For ssh/postgres it resolves the session's
// parties (user/asset/worker) from the live_sessions row, so it MUST run before
// handleSessionEnded deletes that row. The k8s broker instead reports self-contained
// attribution (rec.user_id set): each SessionEnded there names a per-connection
// recording id that never has a live_sessions row (the broker multiplexes many
// connections behind one enrollment/tunnel, not one row per connection), so that case
// trusts the worker-reported parties directly instead of looking them up. Failures are
// returned for the caller to LOG (not fatal to the worker stream): a
// recording-persistence hiccup must never sever the worker's lifeline.
func (s *Handler) persistRecording(ctx context.Context, sessionID string, rec *dataplanev1.RecordingInfo) error {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("bad session id %q: %w", sessionID, err)
	}

	var userID, assetID uuid.UUID
	var workerID, protocol string
	if rec.GetUserId() != "" {
		// Self-contained report (k8s broker): no live_sessions row exists for this
		// per-connection recording id; trust the worker-reported parties.
		if userID, err = uuid.Parse(rec.GetUserId()); err != nil {
			return fmt.Errorf("bad rec user_id: %w", err)
		}
		if assetID, err = uuid.Parse(rec.GetAssetId()); err != nil {
			return fmt.Errorf("bad rec asset_id: %w", err)
		}
		workerID = rec.GetWorkerId()
		protocol = "kubernetes"
	} else {
		parties, perr := sqlc.New(s.pool).GetLiveSessionParties(ctx, sid)
		if perr != nil {
			return fmt.Errorf("lookup session parties: %w", perr)
		}
		userID, assetID, workerID, protocol = parties.UserID, parties.AssetID, parties.WorkerID, parties.Protocol
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	// Attribute the recording to the grant that authorized the session, if the worker
	// reported one. A malformed grant_id is treated as unattributed (NULL) rather than
	// an error — it's worker-reported metadata, not security-load-bearing here.
	var grantID pgtype.UUID
	if g := rec.GetGrantId(); g != "" {
		if u, err := uuid.Parse(g); err == nil {
			grantID = pgconv.UUID(u)
		}
	}

	if err := q.UpsertSessionRecording(ctx, sqlc.UpsertSessionRecordingParams{
		SessionID: sid,
		UserID:    userID,
		AssetID:   assetID,
		WorkerID:  workerID,
		Protocol:  protocol,
		Format:    recordingFormat(protocol),
		GrantID:   grantID,
		ObjectKey: rec.GetObjectKey(),
		SizeBytes: rec.GetSizeBytes(),
		Sha256:    rec.GetSha256(),
		Status:    rec.GetStatus(),
		StartedAt: msToTimestamptz(rec.GetStartedAtUnixMs()),
		EndedAt:   msToTimestamptz(rec.GetEndedAtUnixMs()),
	}); err != nil {
		return fmt.Errorf("upsert session recording: %w", err)
	}

	eventType := EventRecordingCompleted
	if rec.GetStatus() != "completed" {
		eventType = EventRecordingFailed
	}
	detail, _ := json.Marshal(map[string]any{
		"object_key": rec.GetObjectKey(),
		"status":     rec.GetStatus(),
		"size_bytes": rec.GetSizeBytes(),
		"sha256":     rec.GetSha256(),
	})
	if err := audit.New(s.pool).Enqueue(ctx, q, audit.Event{
		Type:    eventType,
		ActorID: userID,
		Subject: "live_session:" + sid.String(),
		Details: detail,
	}); err != nil {
		return fmt.Errorf("enqueue recording audit: %w", err)
	}
	return tx.Commit(ctx)
}

// msToTimestamptz converts a Unix-millisecond timestamp into a Timestamptz, treating
// 0 as "unset" (an invalid/NULL timestamp).
func msToTimestamptz(ms int64) pgtype.Timestamptz {
	if ms == 0 {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: time.UnixMilli(ms).UTC(), Valid: true}
}

// handleSessionEnded removes a live session on a worker's SessionEnded report
// (natural close or a forced-kill confirmation) and audits session.ended. It is
// idempotent (MarkEnded no-ops if the row is already gone), so a duplicate or
// late report is harmless.
func (s *Handler) handleSessionEnded(ctx context.Context, sessionID, reason string) error {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("bad session id %q: %w", sessionID, err)
	}
	return s.terminator.MarkEnded(ctx, sid, reason)
}
