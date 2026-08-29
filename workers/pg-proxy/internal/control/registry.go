// Package control runs the worker's WorkerStream lifeline to warden and tracks
// live sessions for teardown.
package control

import "sync"

// Registry maps a live session id to its cancel func (fired on Teardown).
type Registry struct {
	mu     sync.Mutex
	cancel map[string]func()
}

// NewRegistry returns an empty session registry.
func NewRegistry() *Registry { return &Registry{cancel: map[string]func(){}} }

// Add records a live session and the cancel func that tears it down.
func (r *Registry) Add(sessionID string, cancel func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel[sessionID] = cancel
}

// Remove drops a session without firing its cancel (session ended on its own).
func (r *Registry) Remove(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cancel, sessionID)
}

// Teardown fires and drops a session's cancel; a no-op for unknown ids.
func (r *Registry) Teardown(sessionID string) {
	r.mu.Lock()
	c := r.cancel[sessionID]
	delete(r.cancel, sessionID)
	r.mu.Unlock()
	if c != nil {
		c()
	}
}

// LiveIDs returns the ids of all currently tracked sessions.
func (r *Registry) LiveIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.cancel))
	for id := range r.cancel {
		ids = append(ids, id)
	}
	return ids
}
