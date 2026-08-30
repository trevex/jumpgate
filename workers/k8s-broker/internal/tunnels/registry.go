// Package tunnels tracks connected agent tunnels keyed by asset id.
package tunnels

import (
	"sync"

	"golang.org/x/net/http2"
)

// Registry maps an asset id to the HTTP/2 client conn for that asset's agent tunnel.
type Registry struct {
	mu     sync.RWMutex
	conns  map[string]*http2.ClientConn
	notify chan struct{}
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{conns: map[string]*http2.ClientConn{}, notify: make(chan struct{}, 1)}
}

// Set records (or replaces) the tunnel for assetID.
func (r *Registry) Set(assetID string, cc *http2.ClientConn) {
	r.mu.Lock()
	r.conns[assetID] = cc
	r.mu.Unlock()
	r.signal()
}

// Get returns the tunnel for assetID, or nil.
func (r *Registry) Get(assetID string) *http2.ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[assetID]
}

// Delete removes assetID's tunnel if it is still cc (avoids racing a reconnect
// that already replaced it).
func (r *Registry) Delete(assetID string, cc *http2.ClientConn) {
	r.mu.Lock()
	if r.conns[assetID] == cc {
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
