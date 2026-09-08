// Package broker accepts agent reverse tunnels over mesh mTLS and round-trips
// requests to the right agent by asset id.
package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/workers/k8s-agent/proxy"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/tunnels"
)

// closeWatchInterval is how often a live tunnel is polled for closure.
const closeWatchInterval = 5 * time.Second

// APIServerReport is one agent's API-server identity evidence, relayed to warden
// over the control stream. AgentCertDER is the agent's verified mesh leaf so warden
// binds the observation to the SPIFFE-derived asset id, not the broker's word.
type APIServerReport struct {
	AgentCertDER []byte
	ServerName   string
	ChainDER     [][]byte
}

// Broker holds the agent-tunnel registry and the HTTP/2 client transport.
type Broker struct {
	reg      *tunnels.Registry
	tr       *http2.Transport
	evidence chan APIServerReport
}

// New builds a Broker.
func New() *Broker {
	return &Broker{reg: tunnels.New(), tr: &http2.Transport{AllowHTTP: false}, evidence: make(chan APIServerReport, 16)}
}

// Registry returns the broker's tunnel registry (shared with the warden
// control loop, which advertises its asset set).
func (b *Broker) Registry() *tunnels.Registry { return b.reg }

// Evidence returns the channel of API-server identity reports produced when agents
// connect. The control loop relays them to warden. Buffered; a full buffer drops
// the report (warden re-obtains it on the agent's next reconnect).
func (b *Broker) Evidence() <-chan APIServerReport { return b.evidence }

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
	state := tc.ConnectionState()
	id, err := mesh.IdentityFromConn(state)
	if err != nil {
		slog.Warn("agent identity", "err", err)
		_ = conn.Close()
		return
	}
	assetID := id.ID
	// The agent's verified mesh leaf (DER) travels with every advertisement so warden
	// re-derives the bound asset id from the SPIFFE SAN itself. state.PeerCertificates
	// is non-empty and chain-verified (ServerTLSConfigRole did RequireAndVerifyClientCert).
	certDER := state.PeerCertificates[0].Raw
	cc, err := b.tr.NewClientConn(conn)
	if err != nil {
		slog.Warn("h2 client conn", "err", err)
		_ = conn.Close()
		return
	}
	b.reg.Set(assetID, cc, certDER)
	slog.Info("agent tunnel up", "asset", assetID)
	// Fetch the agent's API-server identity over the freshly-established tunnel and
	// relay it to warden. Non-blocking on its own goroutine so the close-watch loop
	// below still runs promptly.
	go b.fetchAPIServerIdentity(ctx, assetID, certDER, cc)

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

// fetchAPIServerIdentity requests the agent's local API-server identity evidence
// over the tunnel (a reserved path served by the agent, never forwarded to the API
// server) and pushes it to the evidence channel for relay to warden.
func (b *Broker) fetchAPIServerIdentity(ctx context.Context, assetID string, certDER []byte, cc *http2.ClientConn) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://tunnel"+proxy.IdentityPath, nil)
	if err != nil {
		return
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		slog.Warn("fetch agent api-server identity", "asset", assetID, "err", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("agent api-server identity status", "asset", assetID, "status", resp.StatusCode)
		return
	}
	var ident proxy.IdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&ident); err != nil {
		slog.Warn("decode agent api-server identity", "asset", assetID, "err", err)
		return
	}
	report := APIServerReport{AgentCertDER: certDER, ServerName: ident.ServerName, ChainDER: ident.ChainDER}
	select {
	case b.evidence <- report:
	default:
		slog.Warn("evidence buffer full; dropping api-server identity report", "asset", assetID)
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
