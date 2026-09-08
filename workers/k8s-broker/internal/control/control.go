// Package control maintains the k8s-broker's warden control loop: registers,
// heartbeats, and advertises the held agent-tunnel set so warden's registry
// knows which broker holds which cluster's asset tunnel.
package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/broker"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/frontdoor"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/tunnels"
)

const (
	heartbeatInterval = 10 * time.Second
	reconnectBackoff  = 2 * time.Second
)

// Run maintains the WorkerStream lifeline: registers (worker_id=brokerID,
// protocol=kubernetes, dataplane_address), heartbeats, re-advertises the held
// tunnel set on every change, and forwards SessionEnd reports from `ended` as
// SessionEnded frames. Reconnects with backoff until ctx ends.
func Run(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *tunnels.Registry, brokerID, dataplaneAddr string, ended <-chan frontdoor.SessionEnd, evidence <-chan broker.APIServerReport) error {
	for {
		if err := connectAndRun(ctx, client, reg, brokerID, dataplaneAddr, ended, evidence); err != nil && ctx.Err() == nil {
			slog.Warn("worker stream dropped; reconnecting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reconnectBackoff):
		}
	}
}

func connectAndRun(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *tunnels.Registry, brokerID, dataplaneAddr string, ended <-chan frontdoor.SessionEnd, evidence <-chan broker.APIServerReport) error {
	stream := client.WorkerStream(ctx)
	defer func() { _ = stream.CloseRequest() }()
	defer func() { _ = stream.CloseResponse() }()

	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{Register: &dataplanev1.Register{
		WorkerId: brokerID, Protocols: []string{"kubernetes"}, DataplaneAddress: dataplaneAddr,
	}}}); err != nil {
		return err
	}
	if err := advertise(stream, reg); err != nil {
		return err
	}

	recvErr := make(chan error, 1)
	// Comfortably above warden's per-worker probe ceiling (MaxPerWorker, default 2),
	// so the non-blocking-send drop path below is effectively unreachable; 8 is a
	// headroom constant, not a tuned value.
	probeResults := make(chan *dataplanev1.ProbeResult, 8)
	go func() {
		for {
			msg, err := stream.Receive() // drain acks/teardowns; broker has no per-session teardown yet
			if err != nil {
				recvErr <- err
				return
			}
			if pa := msg.GetProbeAssignment(); pa != nil {
				// The k8s-broker has no identity-probe support yet: reply unsupported so
				// the warden lease resolves instead of hanging. Non-blocking.
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
			if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Heartbeat{Heartbeat: &dataplanev1.Heartbeat{}}}); err != nil {
				return err
			}
		case <-reg.Changed():
			if err := advertise(stream, reg); err != nil {
				return err
			}
		case se := <-ended:
			if err := stream.Send(&dataplanev1.WorkerMessage{
				Msg: &dataplanev1.WorkerMessage_SessionEnded{SessionEnded: &dataplanev1.SessionEnded{
					SessionId: se.RecordingID, // per-connection ledger row PK
					Recording: &dataplanev1.RecordingInfo{
						ObjectKey:       se.Report.ObjectKey,
						SizeBytes:       se.Report.SizeBytes,
						Sha256:          se.Report.SHA256Hex,
						StartedAtUnixMs: se.Report.StartedAtMS,
						EndedAtUnixMs:   se.Report.EndedAtMS,
						Status:          se.Report.Status,
						UserId:          se.UserID,
						AssetId:         se.AssetID,
						WorkerId:        brokerID,
						SessionId:       se.SessionID, // token jti cross-ref
					},
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
		case rep := <-evidence:
			if err := stream.Send(&dataplanev1.WorkerMessage{
				Msg: &dataplanev1.WorkerMessage_ApiServerIdentity{ApiServerIdentity: &dataplanev1.ReportApiServerIdentity{
					AgentCertDer: rep.AgentCertDER,
					ServerName:   rep.ServerName,
					ChainDer:     rep.ChainDER,
				}},
			}); err != nil {
				return err
			}
		}
	}
}

// unsupportedProbeResult echoes a probe assignment as a failed, unsupported-protocol
// result, keeping the warden lease resolving until the broker implements probing.
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
		FailureDetail:    "k8s-broker does not implement identity probing",
	}
}

func advertise(stream interface {
	Send(*dataplanev1.WorkerMessage) error
}, reg *tunnels.Registry) error {
	bindings := reg.Bindings()
	agents := make([]*dataplanev1.AgentBinding, 0, len(bindings))
	assetIDs := make([]string, 0, len(bindings))
	for _, b := range bindings {
		agents = append(agents, &dataplanev1.AgentBinding{AgentCertDer: b.CertDER})
		assetIDs = append(assetIDs, b.AssetID) // logging/back-compat; warden re-derives from certs
	}
	return stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_AdvertiseTunnels{
		AdvertiseTunnels: &dataplanev1.AdvertiseTunnels{AssetIds: assetIDs, Agents: agents},
	}})
}
