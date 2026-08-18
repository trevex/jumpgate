package rpc

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
)

// DataplaneServer implements dataplanev1connect.DataplaneServiceHandler: the
// worker lifeline stream (register/heartbeat/session-ended + teardown push) and
// the unary session-setup admission RPC.
type DataplaneServer struct {
	setup    *dataplane.SetupService
	registry *dataplane.Registry
	pool     *pgxpool.Pool
}

// NewDataplaneServer constructs the data-plane RPC implementation.
func NewDataplaneServer(setup *dataplane.SetupService, registry *dataplane.Registry, pool *pgxpool.Pool) *DataplaneServer {
	return &DataplaneServer{setup: setup, registry: registry, pool: pool}
}

// SetupSession redeems a session token: it re-checks authorization, records the
// live session, and issues a JIT SSH certificate. Domain sentinels are mapped to
// Connect codes here; the domain layer stays transport-agnostic.
func (s *DataplaneServer) SetupSession(ctx context.Context, req *connect.Request[dataplanev1.SetupSessionRequest]) (*connect.Response[dataplanev1.SetupSessionResponse], error) {
	out, err := s.setup.Setup(ctx, req.Msg.SessionToken, req.Msg.WorkerId, req.Msg.ClientSshPublicKey)
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
	workerID := reg.WorkerId

	sink := make(chan dataplane.Signal, 64)
	s.registry.Add(workerID, sink)
	defer s.registry.Remove(workerID, sink)

	if err := stream.Send(&dataplanev1.ServerMessage{Msg: &dataplanev1.ServerMessage_Ack{Ack: &dataplanev1.RegisterAck{}}}); err != nil {
		return err
	}

	// Reconnect re-sync (Task 11) — stubbed for now.
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

// reconcileOnRegister re-evaluates this worker's live sessions on (re)connect.
// STUB — implemented in Task 11.
//
// TODO(Task 11): reconcile warden's live_sessions for this worker against the
// worker-reported live IDs and re-push teardown for any that lost authorization
// while the stream was down.
func (s *DataplaneServer) reconcileOnRegister(_ context.Context, _ string, _ []string) error {
	return nil
}

// handleSessionEnded removes a live session on a worker's SessionEnded report.
// STUB — implemented in Task 12.
//
// TODO(Task 12): delete the live_sessions row and emit the session.ended audit
// event when the worker reports a session has ended.
func (s *DataplaneServer) handleSessionEnded(_ context.Context, _, _ string) error {
	return nil
}
