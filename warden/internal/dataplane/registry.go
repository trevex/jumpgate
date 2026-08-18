package dataplane

import "sync"

// Signal is a teardown instruction pushed toward a worker's stream.
type Signal struct {
	SessionID string
	Reason    string
}

// Registry tracks connected workers' teardown sinks. In-memory and ephemeral:
// rebuilt from reconnecting WorkerStreams after a warden restart.
type Registry struct {
	mu    sync.RWMutex
	sinks map[string]map[chan Signal]struct{} // worker_id → set of sinks
}

// NewRegistry constructs an empty worker registry.
func NewRegistry() *Registry { return &Registry{sinks: map[string]map[chan Signal]struct{}{}} }

// Add registers a teardown sink for a worker. A worker may hold multiple sinks
// (e.g. a reconnect racing the old stream's teardown); Push fans out to all.
func (r *Registry) Add(workerID string, ch chan Signal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sinks[workerID] == nil {
		r.sinks[workerID] = map[chan Signal]struct{}{}
	}
	r.sinks[workerID][ch] = struct{}{}
}

// Remove deregisters a teardown sink; the worker entry is dropped once its last
// sink is gone.
func (r *Registry) Remove(workerID string, ch chan Signal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if set := r.sinks[workerID]; set != nil {
		delete(set, ch)
		if len(set) == 0 {
			delete(r.sinks, workerID)
		}
	}
}

// Push sends sig to every sink of worker_id (non-blocking). Reports whether any
// sink was connected.
func (r *Registry) Push(workerID string, sig Signal) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := r.sinks[workerID]
	if len(set) == 0 {
		return false
	}
	delivered := false
	for ch := range set {
		select {
		case ch <- sig:
			delivered = true
		default: // slow consumer; reconnect/pull reconciles
		}
	}
	return delivered
}

// Connected reports whether any stream is currently open for the worker.
func (r *Registry) Connected(workerID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sinks[workerID]) > 0
}
