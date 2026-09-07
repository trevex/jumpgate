package dataplane

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// fakeClock is a hand-advanced clock for deterministic lease-expiry tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeLeasing is a programmable ProbeLeasing. It records every Claim/Complete and
// lets a test drive claim outcomes and completion errors. Concurrency-safe: results
// arrive on worker recv goroutines while the dispatch loop claims.
type fakeLeasing struct {
	mu          sync.Mutex
	claims      []targetidentity.ClaimRequest
	completes   []targetidentity.CompleteRequest
	claimFn     func(targetidentity.ClaimRequest) (targetidentity.ProbeLease, error)
	completeErr error
}

func (f *fakeLeasing) Claim(_ context.Context, req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
	f.mu.Lock()
	f.claims = append(f.claims, req)
	fn := f.claimFn
	f.mu.Unlock()
	if fn == nil {
		return targetidentity.ProbeLease{}, targetidentity.ErrNoProbeAvailable
	}
	return fn(req)
}

func (f *fakeLeasing) Complete(_ context.Context, req targetidentity.CompleteRequest) (targetidentity.VerificationStatus, error) {
	f.mu.Lock()
	f.completes = append(f.completes, req)
	err := f.completeErr
	f.mu.Unlock()
	return targetidentity.StatusProbeFailed, err
}

func (f *fakeLeasing) claimCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.claims)
}

func (f *fakeLeasing) completeReqs() []targetidentity.CompleteRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]targetidentity.CompleteRequest(nil), f.completes...)
}

// leaseFor builds a domain lease matching a claim, with an endpoint appropriate to
// the requested protocol. token is unique per job so completion routing is checkable.
func leaseFor(clock *fakeClock, leaseDur time.Duration, req targetidentity.ClaimRequest, seq byte) targetidentity.ProbeLease {
	addr := "10.0.0.1:22"
	if req.Protocol == targetidentity.ProtocolKubernetes {
		addr = "api.k8s.local"
	}
	return targetidentity.ProbeLease{
		JobID:     uuid.New(),
		AttemptID: uuid.New(),
		Endpoint: targetidentity.Endpoint{
			AssetID: uuid.New(), EndpointRevision: 1, Protocol: req.Protocol, TargetAddress: addr,
		},
		Reason: targetidentity.ProbeReasonOnboarding, AttemptNumber: 1, MaxAttempts: 3,
		ExpiresAt: clock.now().Add(leaseDur), Token: bytes.Repeat([]byte{seq}, targetidentity.LeaseTokenBytes),
	}
}

func newTestDispatcher(leasing ProbeLeasing, maxPerWorker int, clock *fakeClock) *ProbeDispatcher {
	d := NewProbeDispatcher(leasing, ProbeConfig{
		DNSTimeout: 10 * time.Second, ConnectTimeout: 10 * time.Second,
		HandshakeTimeout: 15 * time.Second, TotalTimeout: 30 * time.Second, MaxPerWorker: maxPerWorker,
	})
	if clock != nil {
		d.now = clock.now
	}
	return d
}

func (d *ProbeDispatcher) inflightCount(workerID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if w := d.workers[workerID]; w != nil {
		return len(w.inflight)
	}
	return -1
}

// TestProbeAssignmentWireContainsNoCredentials marshals an assignment and asserts no
// secret-bearing field name or admission token can appear on the wire.
func TestProbeAssignmentWireContainsNoCredentials(t *testing.T) {
	admissionToken := []byte("admission-token-must-not-leak")
	assignment := &dataplanev1.ProbeAssignment{
		JobId: uuid.NewString(), AssetId: uuid.NewString(), EndpointRevision: 1,
		LeaseToken: bytes.Repeat([]byte{0x42}, 32), Protocol: dataplanev1.ProbeProtocol_PROBE_PROTOCOL_SSH,
		Endpoint:             &dataplanev1.ProbeAssignment_Ssh{Ssh: &dataplanev1.SSHProbeEndpoint{Host: "host.test", Port: 22}},
		LeaseExpiresAtUnixMs: 1,
		Limits: &dataplanev1.ProbeLimits{
			DnsTimeoutMs: 10_000, ConnectTimeoutMs: 10_000, HandshakeTimeoutMs: 15_000, TotalTimeoutMs: 30_000,
			MaxBannerBytes: 4096, MaxFrameBytes: 65_536, MaxChainCertificates: 16, MaxCertificateBytes: 65_536, MaxResultBytes: 1 << 20,
		},
	}
	wire, err := proto.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("password"), []byte("private_key"), admissionToken} {
		if bytes.Contains(wire, forbidden) {
			t.Fatalf("probe leaked %q", forbidden)
		}
	}
}

// TestDispatcherBuiltAssignmentHasNoSecrets marshals a dispatcher-produced assignment
// (from a domain lease) and asserts it carries no secret bytes and full limits.
func TestDispatcherBuiltAssignmentHasNoSecrets(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	d := newTestDispatcher(&fakeLeasing{}, 2, clock)
	lease := leaseFor(clock, 30*time.Second, targetidentity.ClaimRequest{Protocol: targetidentity.ProtocolSSH}, 0x11)
	a, err := d.buildAssignment(lease)
	if err != nil {
		t.Fatalf("buildAssignment: %v", err)
	}
	if a.GetLimits().GetTotalTimeoutMs() != 30_000 || a.GetLimits().GetMaxResultBytes() == 0 {
		t.Fatalf("limits not populated: %+v", a.GetLimits())
	}
	wire, err := proto.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("password"), []byte("private_key"), []byte("admission"), []byte("credential")} {
		if bytes.Contains(wire, forbidden) {
			t.Fatalf("assignment leaked %q", forbidden)
		}
	}
}

// TestDispatcherProtocolMatching asserts a worker is only claimed for its advertised
// protocol and the assignment carries the matching typed endpoint. The "kubernetes"
// wire protocol must map to the domain "k8s" protocol.
func TestDispatcherProtocolMatching(t *testing.T) {
	cases := []struct {
		worker   string
		domain   targetidentity.Protocol
		wireEnum dataplanev1.ProbeProtocol
		endpoint func(*dataplanev1.ProbeAssignment) bool
	}{
		{"ssh", targetidentity.ProtocolSSH, dataplanev1.ProbeProtocol_PROBE_PROTOCOL_SSH, func(a *dataplanev1.ProbeAssignment) bool { return a.GetSsh() != nil }},
		{"postgres", targetidentity.ProtocolPostgres, dataplanev1.ProbeProtocol_PROBE_PROTOCOL_POSTGRES, func(a *dataplanev1.ProbeAssignment) bool { return a.GetPostgres() != nil }},
		{"rdp", targetidentity.ProtocolRDP, dataplanev1.ProbeProtocol_PROBE_PROTOCOL_RDP, func(a *dataplanev1.ProbeAssignment) bool { return a.GetRdp() != nil }},
		{"kubernetes", targetidentity.ProtocolKubernetes, dataplanev1.ProbeProtocol_PROBE_PROTOCOL_KUBERNETES, func(a *dataplanev1.ProbeAssignment) bool { return a.GetKubernetes() != nil }},
	}
	for _, tc := range cases {
		t.Run(tc.worker, func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
				return leaseFor(clock, 30*time.Second, req, 0x11), nil
			}}
			d := newTestDispatcher(f, 1, clock)
			sink, release := d.Register("w1", tc.worker)
			defer release()

			d.dispatchOnce(context.Background())

			claims := func() []targetidentity.ClaimRequest { f.mu.Lock(); defer f.mu.Unlock(); return f.claims }()
			if len(claims) != 1 || claims[0].Protocol != tc.domain || claims[0].WorkerID != "w1" {
				t.Fatalf("claims = %+v, want one for protocol %q worker w1", claims, tc.domain)
			}
			a := <-sink
			if a.GetProtocol() != tc.wireEnum || !tc.endpoint(a) {
				t.Fatalf("assignment protocol=%v endpoint mismatch: %+v", a.GetProtocol(), a)
			}
		})
	}
}

// TestDispatcherUnprobeableProtocolIsInert asserts a worker advertising a protocol
// with no probe support is never claimed and gets a nil sink.
func TestDispatcherUnprobeableProtocolIsInert(t *testing.T) {
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		t.Fatalf("claimed unprobeable protocol: %+v", req)
		return targetidentity.ProbeLease{}, nil
	}}
	d := newTestDispatcher(f, 2, nil)
	sink, release := d.Register("w1", "telnet")
	defer release()
	if sink != nil {
		t.Fatal("expected nil sink for unprobeable protocol")
	}
	d.dispatchOnce(context.Background())
	if f.claimCount() != 0 {
		t.Fatalf("claims = %d, want 0", f.claimCount())
	}
}

// TestDispatcherBoundsInFlightPerWorker asserts the dispatcher never leases more than
// MaxPerWorker assignments to one worker until a slot frees.
func TestDispatcherBoundsInFlightPerWorker(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		return leaseFor(clock, 30*time.Second, req, 0x11), nil // always another job available
	}}
	d := newTestDispatcher(f, 2, clock)
	_, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	if got := d.inflightCount("w1"); got != 2 {
		t.Fatalf("in-flight = %d, want 2 (MaxPerWorker)", got)
	}
	if f.claimCount() != 2 {
		t.Fatalf("claims = %d, want 2", f.claimCount())
	}
	// A full worker is not claimed again.
	d.dispatchOnce(context.Background())
	if f.claimCount() != 2 {
		t.Fatalf("claims after second sweep = %d, want 2 (worker full)", f.claimCount())
	}
}

// TestDispatcherStopsOnNoProbeAvailable asserts an empty queue ends the sweep for a
// worker without spinning: one lease then ErrNoProbeAvailable stops at one push.
func TestDispatcherStopsOnNoProbeAvailable(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var n int
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		n++
		if n == 1 {
			return leaseFor(clock, 30*time.Second, req, 0x11), nil
		}
		return targetidentity.ProbeLease{}, targetidentity.ErrNoProbeAvailable
	}}
	d := newTestDispatcher(f, 3, clock)
	_, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	if d.inflightCount("w1") != 1 {
		t.Fatalf("in-flight = %d, want 1", d.inflightCount("w1"))
	}
	if f.claimCount() != 2 {
		t.Fatalf("claims = %d, want 2 (one lease + one empty)", f.claimCount())
	}
}

// TestDispatcherReclaimsLostWorkerSlot asserts a lease that expires without a result
// frees the worker's slot on the next sweep so the job can be re-claimed.
func TestDispatcherReclaimsLostWorkerSlot(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		return leaseFor(clock, 30*time.Second, req, 0x11), nil
	}}
	d := newTestDispatcher(f, 1, clock)
	sink, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	<-sink // consume the assignment; the worker never replies
	if d.inflightCount("w1") != 1 {
		t.Fatalf("in-flight = %d, want 1", d.inflightCount("w1"))
	}
	// Before expiry: the slot stays occupied, no new claim.
	d.dispatchOnce(context.Background())
	if f.claimCount() != 1 {
		t.Fatalf("claims before expiry = %d, want 1", f.claimCount())
	}
	// After expiry: the slot is reclaimed and a fresh probe is claimed.
	clock.advance(31 * time.Second)
	d.dispatchOnce(context.Background())
	if f.claimCount() != 2 {
		t.Fatalf("claims after expiry = %d, want 2 (slot reclaimed)", f.claimCount())
	}
	if d.inflightCount("w1") != 1 {
		t.Fatalf("in-flight after re-claim = %d, want 1", d.inflightCount("w1"))
	}
}

// resultFor builds a worker ProbeResult echoing an assignment (the no-op unsupported
// shape workers reply with until real probing lands).
func resultFor(a *dataplanev1.ProbeAssignment, clock *fakeClock) *dataplanev1.ProbeResult {
	return &dataplanev1.ProbeResult{
		JobId: a.GetJobId(), AssetId: a.GetAssetId(), EndpointRevision: a.GetEndpointRevision(),
		LeaseToken: a.GetLeaseToken(), Protocol: a.GetProtocol(),
		Outcome: dataplanev1.ProbeOutcome_PROBE_OUTCOME_FAILED, ObservedAtUnixMs: clock.now().UnixMilli(),
		FailureCategory: dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_UNSUPPORTED_PROTOCOL,
	}
}

// TestDispatcherRoutesResultToComplete asserts a worker result frees the slot and is
// forwarded to Complete with the authoritative worker id and the lease token.
func TestDispatcherRoutesResultToComplete(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		return leaseFor(clock, 30*time.Second, req, 0x11), nil
	}}
	d := newTestDispatcher(f, 1, clock)
	sink, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	a := <-sink
	d.HandleResult(context.Background(), "w1", resultFor(a, clock))

	if d.inflightCount("w1") != 0 {
		t.Fatalf("in-flight after result = %d, want 0 (slot freed)", d.inflightCount("w1"))
	}
	reqs := f.completeReqs()
	if len(reqs) != 1 {
		t.Fatalf("Complete calls = %d, want 1", len(reqs))
	}
	if reqs[0].WorkerID != "w1" || !bytes.Equal(reqs[0].LeaseToken, a.GetLeaseToken()) || reqs[0].JobID.String() != a.GetJobId() {
		t.Fatalf("Complete req mismatch: %+v", reqs[0])
	}
	if reqs[0].Result.Outcome != targetidentity.ProbeFailed || reqs[0].Result.FailureCategory != targetidentity.FailureNoCompatibleWorker {
		t.Fatalf("mapped result mismatch: %+v", reqs[0].Result)
	}
}

// TestDispatcherIgnoresDuplicateResult asserts a second result for the same job is
// dropped at the dispatcher — Complete runs exactly once (idempotency at the seam).
func TestDispatcherIgnoresDuplicateResult(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		return leaseFor(clock, 30*time.Second, req, 0x11), nil
	}}
	d := newTestDispatcher(f, 1, clock)
	sink, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	a := <-sink
	res := resultFor(a, clock)
	d.HandleResult(context.Background(), "w1", res)
	d.HandleResult(context.Background(), "w1", res) // duplicate

	if got := len(f.completeReqs()); got != 1 {
		t.Fatalf("Complete calls = %d, want 1 (duplicate ignored)", got)
	}
}

// TestDispatcherForwardsStaleResult asserts a result the domain rejects (endpoint
// edited during the lease → ErrStaleRevision) is still forwarded and frees the slot,
// so the re-revised job can be re-claimed on the next sweep.
func TestDispatcherForwardsStaleResult(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := &fakeLeasing{
		claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
			return leaseFor(clock, 30*time.Second, req, 0x11), nil
		},
		completeErr: targetidentity.ErrStaleRevision,
	}
	d := newTestDispatcher(f, 1, clock)
	sink, release := d.Register("w1", "ssh")
	defer release()

	d.dispatchOnce(context.Background())
	a := <-sink
	d.HandleResult(context.Background(), "w1", resultFor(a, clock))

	if len(f.completeReqs()) != 1 {
		t.Fatalf("Complete calls = %d, want 1 (stale still forwarded)", len(f.completeReqs()))
	}
	if d.inflightCount("w1") != 0 {
		t.Fatalf("in-flight after stale result = %d, want 0 (slot freed)", d.inflightCount("w1"))
	}
	// The slot is free, so the next sweep re-claims (into the now-drained sink).
	d.dispatchOnce(context.Background())
	if f.claimCount() != 2 {
		t.Fatalf("claims after stale result = %d, want 2 (slot re-claimed)", f.claimCount())
	}
}

// TestProbeCompleteRequestMapsEvidence asserts the proto→domain result mapping
// carries evidence, metadata, and resolved addresses (the fields real probes fill).
func TestProbeCompleteRequestMapsEvidence(t *testing.T) {
	pr := &dataplanev1.ProbeResult{
		JobId: uuid.NewString(), AssetId: uuid.NewString(), EndpointRevision: 2,
		LeaseToken: bytes.Repeat([]byte{0x7}, 32), Protocol: dataplanev1.ProbeProtocol_PROBE_PROTOCOL_SSH,
		Outcome: dataplanev1.ProbeOutcome_PROBE_OUTCOME_SUCCEEDED, ObservedAtUnixMs: 1_700_000_000_000,
		ResolvedAddresses: []string{"192.0.2.1"},
		Evidence: []*dataplanev1.ProbeEvidence{{
			Kind:      dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_SSH_HOST_KEY,
			Algorithm: "ssh-ed25519", Sha256Fingerprint: "SHA256:abc", PublicMaterial: "AAAA",
			DnsNames: []string{"host.test"}, KeyBits: 256, KeyCurve: "ed25519",
			DisplayExtensions: []*dataplanev1.ProbeDisplayExtension{{Name: "n", Value: "v"}},
		}},
		ProtocolMetadata: &dataplanev1.ProbeResult_Ssh{Ssh: &dataplanev1.ProbeSSHMetadata{Banner: "SSH-2.0-x", HostKeyAlgorithms: []string{"ssh-ed25519"}}},
	}
	jobID, err := uuid.Parse(pr.GetJobId())
	if err != nil {
		t.Fatalf("parse job id: %v", err)
	}
	req := probeCompleteRequest("w9", jobID, pr)
	if req.WorkerID != "w9" || req.Result.Outcome != targetidentity.ProbeSucceeded {
		t.Fatalf("basics mismatch: %+v", req)
	}
	if len(req.Result.ResolvedAddresses) != 1 || req.Result.ResolvedAddresses[0] != "192.0.2.1" {
		t.Fatalf("addresses mismatch: %+v", req.Result.ResolvedAddresses)
	}
	if len(req.Result.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(req.Result.Evidence))
	}
	ev := req.Result.Evidence[0]
	if ev.Kind != targetidentity.EvidenceSSHHostKey || ev.Algorithm != "ssh-ed25519" || ev.Fingerprint != "SHA256:abc" {
		t.Fatalf("evidence mapping mismatch: %+v", ev)
	}
	if ev.Key.Bits != 256 || ev.Key.Curve != "ed25519" || len(ev.DisplayExtensions) != 1 || ev.DisplayExtensions[0].Name != "n" {
		t.Fatalf("evidence detail mapping mismatch: %+v", ev)
	}
	if req.Result.SSH == nil || req.Result.SSH.Banner != "SSH-2.0-x" {
		t.Fatalf("ssh metadata mapping mismatch: %+v", req.Result.SSH)
	}
	if req.Result.ObservedAt.IsZero() {
		t.Fatal("observed_at not mapped")
	}
}

// TestDispatcherConcurrentEnqueueAndFree runs the dispatch loop and per-worker result
// draining concurrently so `go test -race` actually sees the enqueue-vs-free
// interleaving on w.inflight. It asserts the per-worker in-flight bound is never
// exceeded and every pushed assignment is Completed exactly once with no leak.
func TestDispatcherConcurrentEnqueueAndFree(t *testing.T) {
	const workers = 3
	const maxPerWorker = 2
	const iterations = 500

	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)} // frozen: nothing expires mid-run
	f := &fakeLeasing{claimFn: func(req targetidentity.ClaimRequest) (targetidentity.ProbeLease, error) {
		return leaseFor(clock, 30*time.Second, req, 0x11), nil // effectively unbounded supply
	}}
	d := newTestDispatcher(f, maxPerWorker, clock)

	ids := make([]string, workers)
	sinks := make([]<-chan *dataplanev1.ProbeAssignment, workers)
	for i := range workers {
		ids[i] = fmt.Sprintf("w%d", i)
		sink, release := d.Register(ids[i], "ssh")
		defer release()
		sinks[i] = sink
	}

	var pushed atomic.Int64
	dispatchDone := make(chan struct{})
	var wg sync.WaitGroup

	// Dispatcher: claim+enqueue in a bounded loop, sampling the bound after each sweep.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(dispatchDone)
		for range iterations {
			d.dispatchOnce(context.Background())
			for _, id := range ids {
				if got := d.inflightCount(id); got > maxPerWorker {
					t.Errorf("in-flight for %s = %d, exceeds MaxPerWorker %d", id, got, maxPerWorker)
				}
			}
			runtime.Gosched() // yield so drainers interleave
		}
	}()

	// Drainers: free each worker's slot and Complete it. On dispatch stop, drain the
	// finite remainder (no enqueues can arrive after dispatchDone).
	for i := range workers {
		wg.Add(1)
		id, sink := ids[i], sinks[i]
		go func() {
			defer wg.Done()
			handle := func(a *dataplanev1.ProbeAssignment) {
				pushed.Add(1)
				d.HandleResult(context.Background(), id, resultFor(a, clock))
			}
			for {
				select {
				case <-dispatchDone:
					for {
						select {
						case a := <-sink:
							handle(a)
						default:
							return
						}
					}
				case a := <-sink:
					handle(a)
				}
			}
		}()
	}
	wg.Wait()

	completes := f.completeReqs()
	if int64(len(completes)) != pushed.Load() {
		t.Fatalf("Complete calls = %d, want %d (one per pushed assignment)", len(completes), pushed.Load())
	}
	seen := make(map[uuid.UUID]bool, len(completes))
	for _, c := range completes {
		if seen[c.JobID] {
			t.Fatalf("job %s completed twice (double slot)", c.JobID)
		}
		seen[c.JobID] = true
	}
	for _, id := range ids {
		if got := d.inflightCount(id); got != 0 {
			t.Fatalf("%s leaked %d in-flight after drain", id, got)
		}
	}
	if pushed.Load() == 0 {
		t.Fatal("no assignments were dispatched; test exercised nothing")
	}
}

// TestDispatcherReconnectRaceKeepsNewGeneration asserts a stale stream's release does
// not evict a worker that has already reconnected under a newer generation.
func TestDispatcherReconnectRaceKeepsNewGeneration(t *testing.T) {
	d := newTestDispatcher(&fakeLeasing{}, 1, nil)
	_, releaseOld := d.Register("w1", "ssh")
	_, releaseNew := d.Register("w1", "ssh") // reconnect: newer generation supersedes
	defer releaseNew()

	releaseOld() // stale stream cleanup must be a no-op
	if d.inflightCount("w1") != 0 {
		t.Fatal("reconnected worker was evicted by the stale stream's release")
	}
	d.mu.Lock()
	_, present := d.workers["w1"]
	d.mu.Unlock()
	if !present {
		t.Fatal("worker missing after stale release; reconnect generation not honored")
	}
}
