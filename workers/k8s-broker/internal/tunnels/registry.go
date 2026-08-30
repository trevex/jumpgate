// Package tunnels tracks connected agent tunnels keyed by asset id.
package tunnels

import (
	"sync"

	"golang.org/x/net/http2"
)

// Registry maps an asset id to the HTTP/2 client conn for that asset's agent tunnel.
type Registry struct {
	mu    sync.RWMutex
	conns map[string]*http2.ClientConn
}

// New returns an empty registry.
func New() *Registry { return &Registry{conns: map[string]*http2.ClientConn{}} }

// Set records (or replaces) the tunnel for assetID.
func (r *Registry) Set(assetID string, cc *http2.ClientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[assetID] = cc
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
	defer r.mu.Unlock()
	if r.conns[assetID] == cc {
		delete(r.conns, assetID)
	}
}
