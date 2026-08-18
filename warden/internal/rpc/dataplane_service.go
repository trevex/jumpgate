package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/mesh"
)

// workerIdentity returns the authoritative worker id from the request's mesh
// identity, enforcing that the caller presented a `worker`-role mesh cert whose
// SAN id equals claimedID. Enforcement is UNCONDITIONAL: no mesh identity in ctx
// (illegitimate on the mesh listener, where mTLS guarantees identity) or a claim
// that differs from the cert → PermissionDenied.
func workerIdentity(ctx context.Context, claimedID string) (string, error) {
	id, ok := mesh.IdentityFromContext(ctx)
	if !ok || id.Role != "worker" {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("worker mesh identity required"))
	}
	if claimedID != id.ID {
		return "", connect.NewError(connect.CodePermissionDenied, fmt.Errorf("worker_id %q does not match cert identity %q", claimedID, id.ID))
	}
	return id.ID, nil
}

// DataplaneServer implements dataplanev1connect.DataplaneServiceHandler: the
// worker lifeline stream (register/heartbeat/session-ended + teardown push) and
// the unary session-setup admission RPC.
type DataplaneServer struct {
	setup      *dataplane.SetupService
	registry   *dataplane.Registry
	pool       *pgxpool.Pool
	terminator *dataplane.Terminator
}

// NewDataplaneServer constructs the data-plane RPC implementation.
func NewDataplaneServer(setup *dataplane.SetupService, registry *dataplane.Registry, pool *pgxpool.Pool, terminator *dataplane.Terminator) *DataplaneServer {
	return &DataplaneServer{setup: setup, registry: registry, pool: pool, terminator: terminator}
}

// SetupSession redeems a session token: it re-checks authorization, records the
// live session, and issues a JIT SSH certificate. Domain sentinels are mapped to
// Connect codes here; the domain layer stays transport-agnostic.
func (s *DataplaneServer) SetupSession(ctx context.Context, req *connect.Request[dataplanev1.SetupSessionRequest]) (*connect.Response[dataplanev1.SetupSessionResponse], error) {
	// Derive the authoritative worker id from the mTLS cert SAN; the request must
	// not claim a different worker than its certificate (else PermissionDenied).
	workerID, err := workerIdentity(ctx, req.Msg.WorkerId)
	if err != nil {
		return nil, err
	}
	out, err := s.setup.Setup(ctx, req.Msg.SessionToken, workerID, req.Msg.ClientSshPublicKey)
	switch {
	case errors.Is(err, dataplane.ErrBadToken), errors.Is(err, dataplane.ErrKeyMismatch):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, dataplane.ErrNotAuthorized):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, dataplane.ErrReplay):
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, dataplane.ErrNoTarget):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&dataplanev1.SetupSessionResponse{
		TargetAddress:  out.TargetAddress,
		SshCertificate: out.SSHCertificate,
	}), nil
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
func (s *DataplaneServer) WorkerStream(ctx context.Context, stream *connect.BidiStream[dataplanev1.WorkerMessage, dataplanev1.ServerMessage]) error {
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

	sink := make(chan dataplane.Signal, 64)
	s.registry.Add(workerID, sink)
	defer s.registry.Remove(workerID, sink)

	s.registry.SetWorkerMeta(workerID, dataplane.WorkerMeta{
		Protocol: firstProtocolOr(reg.Protocols, "ssh"),
		Address:  reg.DataplaneAddress,
		Capacity: reg.Capacity,
	})
	defer s.registry.ClearWorkerMeta(workerID)

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
				if err := s.handleSessionEnded(ctx, se.SessionId, se.Reason); err != nil {
					slog.Error("session ended handling failed", "session_id", se.SessionId, "err", err)
				}
			}
			// Heartbeat / Register(after first): no-op.
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
func (s *DataplaneServer) reconcileOnRegister(ctx context.Context, workerID string, workerLiveIDs []string) error {
	have := make(map[string]bool, len(workerLiveIDs))
	for _, id := range workerLiveIDs {
		have[id] = true
	}
	rows, err := gen.New(s.pool).ListLiveSessionsByWorker(ctx, workerID)
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

// handleSessionEnded removes a live session on a worker's SessionEnded report
// (natural close or a forced-kill confirmation) and audits session.ended. It is
// idempotent (MarkEnded no-ops if the row is already gone), so a duplicate or
// late report is harmless.
func (s *DataplaneServer) handleSessionEnded(ctx context.Context, sessionID, reason string) error {
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("bad session id %q: %w", sessionID, err)
	}
	return s.terminator.MarkEnded(ctx, sid, reason)
}
