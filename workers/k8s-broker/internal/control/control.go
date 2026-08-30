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

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/tunnels"
)

const (
	heartbeatInterval = 10 * time.Second
	reconnectBackoff  = 2 * time.Second
)

// Run maintains the WorkerStream lifeline: registers (worker_id=brokerID,
// protocol=kubernetes, dataplane_address), heartbeats, and re-advertises the
// held tunnel set on every change. Reconnects with backoff until ctx ends.
func Run(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *tunnels.Registry, brokerID, dataplaneAddr string) error {
	for {
		if err := connectAndRun(ctx, client, reg, brokerID, dataplaneAddr); err != nil && ctx.Err() == nil {
			slog.Warn("worker stream dropped; reconnecting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(reconnectBackoff):
		}
	}
}

func connectAndRun(ctx context.Context, client dataplanev1connect.DataplaneServiceClient, reg *tunnels.Registry, brokerID, dataplaneAddr string) error {
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
	go func() {
		for {
			if _, err := stream.Receive(); err != nil { // drain acks/teardowns; broker has no per-session teardown yet
				recvErr <- err
				return
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
		}
	}
}

func advertise(stream interface {
	Send(*dataplanev1.WorkerMessage) error
}, reg *tunnels.Registry) error {
	return stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_AdvertiseTunnels{
		AdvertiseTunnels: &dataplanev1.AdvertiseTunnels{AssetIds: reg.AssetIDs()},
	}})
}
