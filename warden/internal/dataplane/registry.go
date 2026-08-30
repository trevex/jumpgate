package dataplane

import "sync"

// Signal is a teardown instruction pushed toward a worker's stream.
type Signal struct {
	SessionID string
	Reason    string
}

// WorkerMeta is a worker's routing metadata for the gateway roster.
type WorkerMeta struct {
	Protocol string
	Address  string // data-plane listen address the gateway dials
	Capacity int32
}

// RosterKind discriminates roster deltas.
type RosterKind int

const (
	// RosterAdded marks a worker appearing in the roster (snapshot or live add).
	RosterAdded RosterKind = iota
	// RosterRemoved marks a worker leaving the roster.
	RosterRemoved
)

// RosterWorker is a worker as seen by the gateway roster.
type RosterWorker struct {
	WorkerID string
	Protocol string
	Address  string
	Capacity int32
}

// RosterEvent is a snapshot entry or a live delta.
type RosterEvent struct {
	Kind   RosterKind
	Worker RosterWorker
}

// Registry tracks connected workers' teardown sinks and roster metadata. In-memory
// and ephemeral: rebuilt from reconnecting WorkerStreams after a warden restart.
type Registry struct {
	mu         sync.RWMutex
	sinks      map[string]map[chan Signal]struct{} // worker_id → set of sinks
	meta       map[string]WorkerMeta               // worker_id → routing metadata
	rosterSubs map[chan RosterEvent]struct{}       // active roster subscribers
	tunnels    map[string]string                   // asset_id → broker worker_id
}

// NewRegistry constructs an empty worker registry.
func NewRegistry() *Registry {
	return &Registry{
		sinks:      map[string]map[chan Signal]struct{}{},
		meta:       map[string]WorkerMeta{},
		rosterSubs: map[chan RosterEvent]struct{}{},
		tunnels:    map[string]string{},
	}
}

// SetTunnels replaces brokerID's advertised asset set. Assets no longer listed by
// this broker are dropped; an asset now claimed by brokerID is (re)assigned to it.
func (r *Registry) SetTunnels(brokerID string, assetIDs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Drop this broker's stale entries.
	for a, b := range r.tunnels {
		if b == brokerID {
			delete(r.tunnels, a)
		}
	}
	for _, a := range assetIDs {
		r.tunnels[a] = brokerID
	}
}

// ClearTunnels drops every asset advertised by brokerID (on disconnect).
func (r *Registry) ClearTunnels(brokerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for a, b := range r.tunnels {
		if b == brokerID {
			delete(r.tunnels, a)
		}
	}
}

// BrokerForAsset returns the broker id currently holding assetID's agent tunnel.
func (r *Registry) BrokerForAsset(assetID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.tunnels[assetID]
	return id, ok
}

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

// ConnectedWorkers returns the ids of workers with a live stream on this replica.
func (r *Registry) ConnectedWorkers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.sinks))
	for id, set := range r.sinks {
		if len(set) > 0 {
			out = append(out, id)
		}
	}
	return out
}

// SetWorkerMeta records a worker's routing metadata and broadcasts a RosterAdded
// event to all current subscribers (non-blocking: a slow/cancelled subscriber is
// skipped, never blocks the caller).
func (r *Registry) SetWorkerMeta(workerID string, m WorkerMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.meta[workerID] = m
	r.broadcastLocked(RosterEvent{
		Kind: RosterAdded,
		Worker: RosterWorker{
			WorkerID: workerID,
			Protocol: m.Protocol,
			Address:  m.Address,
			Capacity: m.Capacity,
		},
	})
}

// ClearWorkerMeta drops a worker's routing metadata and broadcasts a RosterRemoved
// event. No-op if the worker had no metadata.
func (r *Registry) ClearWorkerMeta(workerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.meta[workerID]; !ok {
		return
	}
	delete(r.meta, workerID)
	r.broadcastLocked(RosterEvent{
		Kind:   RosterRemoved,
		Worker: RosterWorker{WorkerID: workerID},
	})
}

// broadcastLocked fans ev out to every current subscriber, non-blocking. The
// caller must hold r.mu; since cancel removes-then-closes a subscriber under the
// same lock, we never send on a closed channel here.
func (r *Registry) broadcastLocked(ev RosterEvent) {
	for ch := range r.rosterSubs {
		select {
		case ch <- ev:
		default: // slow/full subscriber; it will resync via a fresh snapshot
		}
	}
}

// SubscribeRoster returns a channel that first receives a RosterAdded snapshot of
// every currently-known worker, then live RosterAdded/RosterRemoved deltas. The
// returned cancel func unsubscribes and closes the channel; it is safe to call
// multiple times. Sends to the channel are always non-blocking, so a slow or
// cancelled subscriber never blocks SetWorkerMeta/ClearWorkerMeta.
func (r *Registry) SubscribeRoster() (<-chan RosterEvent, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()

	bufSize := 64
	if n := len(r.meta) + 16; n > bufSize {
		bufSize = n
	}
	ch := make(chan RosterEvent, bufSize)

	// Pre-fill the snapshot before any concurrent delta can be broadcast: we hold
	// the lock, so no SetWorkerMeta/ClearWorkerMeta can interleave.
	for id, m := range r.meta {
		select {
		case ch <- RosterEvent{
			Kind: RosterAdded,
			Worker: RosterWorker{
				WorkerID: id,
				Protocol: m.Protocol,
				Address:  m.Address,
				Capacity: m.Capacity,
			},
		}:
		default:
		}
	}
	r.rosterSubs[ch] = struct{}{}

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			delete(r.rosterSubs, ch) // remove before close so broadcasts skip it
			close(ch)
		})
	}
	return ch, cancel
}
