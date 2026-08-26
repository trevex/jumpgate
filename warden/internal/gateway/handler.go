// Package gateway assembles the mesh-facing GatewayService handler served on
// warden's mTLS listener.
package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"

	"connectrpc.com/connect"

	gatewayv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/mesh"
)

// Handler implements gatewayv1connect.GatewayServiceHandler. It is served on
// warden's mesh (mTLS) listener; every call requires the `gateway` mesh identity.
type Handler struct {
	registry *dataplane.Registry
	pubKey   ed25519.PublicKey
}

// NewHandler constructs the gateway-facing RPC implementation. pubKey is the
// active session signing public key, loaded once at startup.
func NewHandler(registry *dataplane.Registry, pubKey ed25519.PublicKey) *Handler {
	return &Handler{registry: registry, pubKey: pubKey}
}

// requireGateway rejects any call whose mesh identity is not the gateway role.
func requireGateway(ctx context.Context) error {
	id, ok := mesh.IdentityFromContext(ctx)
	if !ok || id.Role != "gateway" {
		return connect.NewError(connect.CodePermissionDenied, errors.New("gateway identity required"))
	}
	return nil
}

// WatchWorkers streams the worker roster to the gateway: an initial snapshot of
// every currently-known worker followed by live added/removed deltas. The stream
// stays open until the gateway disconnects or ctx is cancelled.
func (s *Handler) WatchWorkers(ctx context.Context, _ *connect.Request[gatewayv1.WatchWorkersRequest], stream *connect.ServerStream[gatewayv1.RosterEvent]) error {
	if err := requireGateway(ctx); err != nil {
		return err
	}
	sub, cancel := s.registry.SubscribeRoster()
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-sub:
			kind := gatewayv1.RosterEvent_ADDED
			if ev.Kind == dataplane.RosterRemoved {
				kind = gatewayv1.RosterEvent_REMOVED
			}
			if err := stream.Send(&gatewayv1.RosterEvent{
				Kind: kind,
				Worker: &gatewayv1.Worker{
					WorkerId:         ev.Worker.WorkerID,
					Protocol:         ev.Worker.Protocol,
					DataplaneAddress: ev.Worker.Address,
					Capacity:         ev.Worker.Capacity,
				},
			}); err != nil {
				return err
			}
		}
	}
}

// GetSessionVerificationKey returns the Ed25519 public key the gateway uses to
// verify session tokens offline.
func (s *Handler) GetSessionVerificationKey(ctx context.Context, _ *connect.Request[gatewayv1.GetSessionVerificationKeyRequest]) (*connect.Response[gatewayv1.GetSessionVerificationKeyResponse], error) {
	if err := requireGateway(ctx); err != nil {
		return nil, err
	}
	if len(s.pubKey) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("session signing key not initialized"))
	}
	return connect.NewResponse(&gatewayv1.GetSessionVerificationKeyResponse{Ed25519PublicKey: s.pubKey}), nil
}
