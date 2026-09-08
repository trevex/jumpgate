// Package tunnels tracks connected agent tunnels keyed by asset id.
package tunnels

import (
	"sync"

	"golang.org/x/net/http2"
)

// tunnel is one held agent connection plus the agent's verified mesh leaf cert
// (DER) captured from the mTLS handshake. The cert is relayed to warden so it
// re-derives the bound asset id from the SPIFFE SAN rather than trusting the
// broker's advertised list.
type tunnel struct {
	cc      *http2.ClientConn
	certDER []byte
}

// Binding is one advertised agent tunnel: its asset id and the agent's verified
// mesh leaf certificate (DER).
type Binding struct {
	AssetID string
	CertDER []byte
}

// Registry maps an asset id to the HTTP/2 client conn for that asset's agent tunnel.
type Registry struct {
	mu     sync.RWMutex
	conns  map[string]tunnel
	notify chan struct{}
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{conns: map[string]tunnel{}, notify: make(chan struct{}, 1)}
}

// Set records (or replaces) the tunnel for assetID along with the agent's verified
// mesh leaf cert (DER).
func (r *Registry) Set(assetID string, cc *http2.ClientConn, certDER []byte) {
	r.mu.Lock()
	r.conns[assetID] = tunnel{cc: cc, certDER: certDER}
	r.mu.Unlock()
	r.signal()
}

// Get returns the tunnel conn for assetID, or nil.
func (r *Registry) Get(assetID string) *http2.ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[assetID].cc
}

// Delete removes assetID's tunnel if it is still cc (avoids racing a reconnect
// that already replaced it).
func (r *Registry) Delete(assetID string, cc *http2.ClientConn) {
	r.mu.Lock()
	if r.conns[assetID].cc == cc {
		delete(r.conns, assetID)
	}
	r.mu.Unlock()
	r.signal()
}

// AssetIDs returns the currently held asset ids (unordered).
func (r *Registry) AssetIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.conns))
	for a := range r.conns {
		out = append(out, a)
	}
	return out
}

// Bindings returns the currently held tunnels as asset-id + agent-cert pairs, for
// advertisement to warden (which re-derives asset ids from the certs).
func (r *Registry) Bindings() []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Binding, 0, len(r.conns))
	for a, t := range r.conns {
		out = append(out, Binding{AssetID: a, CertDER: t.certDER})
	}
	return out
}

// Changed returns a channel that receives (coalesced) whenever the tunnel set
// changes. Set/Delete signal it non-blocking, so a burst of changes collapses
// into a single pending notification.
func (r *Registry) Changed() <-chan struct{} { return r.notify }

func (r *Registry) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}
