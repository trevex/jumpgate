// Package broker accepts agent reverse tunnels over mesh mTLS and round-trips
// requests to the right agent by asset id.
package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/tunnels"
)

// closeWatchInterval is how often a live tunnel is polled for closure.
const closeWatchInterval = 5 * time.Second

// Broker holds the agent-tunnel registry and the HTTP/2 client transport.
type Broker struct {
	reg *tunnels.Registry
	tr  *http2.Transport
}

// New builds a Broker.
func New() *Broker {
	return &Broker{reg: tunnels.New(), tr: &http2.Transport{AllowHTTP: false}}
}

// Serve accepts mesh mTLS agent connections on ln until ctx ends. Each accepted
// conn: verify agent identity, become the HTTP/2 CLIENT over the conn (role
// reversal — the agent is the HTTP/2 server), and register it by asset id.
func (b *Broker) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("accept", "err", err)
			continue
		}
		go b.handleAgent(ctx, conn)
	}
}

func (b *Broker) handleAgent(ctx context.Context, conn net.Conn) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return
	}
	id, err := mesh.IdentityFromConn(tc.ConnectionState())
	if err != nil {
		slog.Warn("agent identity", "err", err)
		_ = conn.Close()
		return
	}
	assetID := id.ID
	cc, err := b.tr.NewClientConn(conn)
	if err != nil {
		slog.Warn("h2 client conn", "err", err)
		_ = conn.Close()
		return
	}
	b.reg.Set(assetID, cc)
	slog.Info("agent tunnel up", "asset", assetID)

	// Block until the conn dies (or ctx ends), then drop it from the registry.
	// *http2.ClientConn exposes no blocking "closed" channel, so poll State():
	// drop when the conn is closed, or closing and fully drained.
	for {
		select {
		case <-ctx.Done():
			b.reg.Delete(assetID, cc)
			_ = conn.Close()
			return
		case <-time.After(closeWatchInterval):
			if st := cc.State(); st.Closed || (st.Closing && st.StreamsActive == 0) {
				b.reg.Delete(assetID, cc)
				_ = conn.Close()
				slog.Info("agent tunnel down", "asset", assetID)
				return
			}
		}
	}
}

// RoundTrip forwards req to the agent tunnel for assetID. Returns an error if no
// agent is connected for that asset.
func (b *Broker) RoundTrip(assetID string, req *http.Request) (*http.Response, error) {
	cc := b.reg.Get(assetID)
	if cc == nil {
		return nil, fmt.Errorf("no agent tunnel for asset %s", assetID)
	}
	return cc.RoundTrip(req)
}
