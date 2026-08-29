package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
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

// SessionEnd is a finished-session report pushed by the data-plane path (later
// plan) for the control loop to forward to warden as a SessionEnded frame.
type SessionEnd struct {
	SessionID string
	Reason    string
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

	// The control loop is the single writer of the stream; the receive path
	// runs in its own goroutine and reports errors back over recvErr.
	recvErr := make(chan error, 1)
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
				}},
			}); err != nil {
				return err
			}
		}
	}
}
