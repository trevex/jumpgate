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
				// pg-proxy has no identity-probe support yet: reply unsupported so the
				// warden lease resolves instead of hanging. Non-blocking; a full buffer
				// just lets the lease expire.
				select {
				case probeResults <- unsupportedProbeResult(pa):
				default:
					slog.Warn("probe result buffer full; dropping unsupported reply", "job_id", pa.GetJobId())
				}
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

// unsupportedProbeResult echoes a probe assignment as a failed, unsupported-protocol
// result. It keeps the warden lease resolving until pg-proxy implements real probing.
func unsupportedProbeResult(pa *dataplanev1.ProbeAssignment) *dataplanev1.ProbeResult {
	return &dataplanev1.ProbeResult{
		JobId:            pa.GetJobId(),
		AssetId:          pa.GetAssetId(),
		EndpointRevision: pa.GetEndpointRevision(),
		LeaseToken:       pa.GetLeaseToken(),
		Protocol:         pa.GetProtocol(),
		Outcome:          dataplanev1.ProbeOutcome_PROBE_OUTCOME_FAILED,
		ObservedAtUnixMs: time.Now().UnixMilli(),
		FailureCategory:  dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_UNSUPPORTED_PROTOCOL,
		FailureDetail:    "pg-proxy does not implement identity probing",
	}
}
