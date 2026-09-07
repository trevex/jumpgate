package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// Byte/count ceilings warden imposes on a probe worker's parsing and result size.
// They are bounded by (and never exceed) the domain's public-material limits so a
// worker can never persist more than the domain would accept; the proto validates
// each against the same upper bounds.
const (
	probeMaxBannerBytes       = 4 << 10  // 4 KiB SSH banner
	probeMaxFrameBytes        = 64 << 10 // 64 KiB single protocol frame
	probeMaxChainCertificates = 16       // TLS chain depth
	probeMaxCertificateBytes  = 64 << 10 // 64 KiB per certificate
	probeMaxResultBytes       = 1 << 20  // 1 MiB whole result
)

// probeDispatchInterval is the retry-sweep backstop: every tick the dispatcher
// reclaims worker slots whose lease expired and claims queued jobs to refill free
// slots. Lease expiry and retry exhaustion are enforced DB-side (Service.Claim),
// so the sweep only re-attempts Claim — it never reimplements lease bookkeeping.
//
// ponytail: fixed backstop tick; add a queue NOTIFY wakeup if probe dispatch
// latency (up to one interval) ever matters.
const probeDispatchInterval = 5 * time.Second

// ProbeLeasing is the subset of the target-identity domain the dispatcher consumes.
// *targetidentity.Service satisfies it; tests substitute a fake to drive lease
// accounting without a database.
type ProbeLeasing interface {
	Claim(context.Context, targetidentity.ClaimRequest) (targetidentity.ProbeLease, error)
	Complete(context.Context, targetidentity.CompleteRequest) (targetidentity.VerificationStatus, error)
}

// ProbeConfig carries the operator-set probe execution bounds. The byte/count
// ceilings are fixed package constants; only the stage timeouts and the per-worker
// concurrency cap are configurable.
type ProbeConfig struct {
	DNSTimeout       time.Duration
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	TotalTimeout     time.Duration
	MaxPerWorker     int
}

// probeWorker is one connected worker's probe routing state: the sink its stream
// selects on and the set of assignments leased to it but not yet resulted (each
// keyed by job id, valued by its lease expiry so a lost worker's slots free).
type probeWorker struct {
	protocol targetidentity.Protocol
	sink     chan *dataplanev1.ProbeAssignment
	inflight map[uuid.UUID]time.Time
	gen      uint64
}

// ProbeDispatcher leases durable identity probes to protocol-compatible workers and
// routes their results back to the domain. It bounds in-flight assignments per
// worker (ProbeConfig.MaxPerWorker); everything else — lease expiry, retry counting,
// exhaustion — lives in the database behind Service.Claim/Complete.
type ProbeDispatcher struct {
	leasing      ProbeLeasing
	limits       *dataplanev1.ProbeLimits
	maxPerWorker int
	now          func() time.Time

	mu      sync.Mutex
	workers map[string]*probeWorker
	gen     atomic.Uint64
}

// NewProbeDispatcher constructs a dispatcher over the target-identity domain.
func NewProbeDispatcher(leasing ProbeLeasing, cfg ProbeConfig) *ProbeDispatcher {
	maxPerWorker := cfg.MaxPerWorker
	if maxPerWorker < 1 {
		maxPerWorker = 1
	}
	return &ProbeDispatcher{
		leasing:      leasing,
		maxPerWorker: maxPerWorker,
		now:          time.Now,
		workers:      map[string]*probeWorker{},
		limits: &dataplanev1.ProbeLimits{
			DnsTimeoutMs:         cfg.DNSTimeout.Milliseconds(),
			ConnectTimeoutMs:     cfg.ConnectTimeout.Milliseconds(),
			HandshakeTimeoutMs:   cfg.HandshakeTimeout.Milliseconds(),
			TotalTimeoutMs:       cfg.TotalTimeout.Milliseconds(),
			MaxBannerBytes:       probeMaxBannerBytes,
			MaxFrameBytes:        probeMaxFrameBytes,
			MaxChainCertificates: probeMaxChainCertificates,
			MaxCertificateBytes:  probeMaxCertificateBytes,
			MaxResultBytes:       probeMaxResultBytes,
		},
	}
}

// Register enrolls a connected worker's probe sink for the given advertised
// protocol and returns the channel its stream selects on plus a release func to
// call on stream exit. A protocol that cannot be probed yields a nil channel and a
// no-op release (the worker is simply never assigned a probe). Reconnect races are
// resolved by generation, mirroring Registry.ClaimWorker/ReleaseWorker: a stale
// stream's release only clears the entry it still owns.
func (d *ProbeDispatcher) Register(workerID, protocol string) (<-chan *dataplanev1.ProbeAssignment, func()) {
	domain, ok := domainProtocol(protocol)
	if !ok {
		return nil, func() {}
	}
	gen := d.gen.Add(1)
	w := &probeWorker{
		protocol: domain,
		sink:     make(chan *dataplanev1.ProbeAssignment, d.maxPerWorker),
		inflight: map[uuid.UUID]time.Time{},
		gen:      gen,
	}
	d.mu.Lock()
	d.workers[workerID] = w
	d.mu.Unlock()
	return w.sink, func() {
		d.mu.Lock()
		if cur := d.workers[workerID]; cur != nil && cur.gen == gen {
			delete(d.workers, workerID)
		}
		d.mu.Unlock()
	}
}

// HandleResult routes a worker's ProbeResult to the domain. It frees the worker's
// in-flight slot first; an untracked result (duplicate, stale, or from an
// assignment this dispatcher never made) is dropped without a Complete — the
// domain lease it referenced, if any, is already resolved or will expire.
func (d *ProbeDispatcher) HandleResult(ctx context.Context, workerID string, pr *dataplanev1.ProbeResult) {
	jobID, err := uuid.Parse(pr.GetJobId())
	if err != nil {
		slog.Warn("probe result with unparseable job id", "worker_id", workerID, "err", err)
		return
	}
	d.mu.Lock()
	w := d.workers[workerID]
	tracked := false
	if w != nil {
		if _, ok := w.inflight[jobID]; ok {
			delete(w.inflight, jobID)
			tracked = true
		}
	}
	d.mu.Unlock()
	if !tracked {
		slog.Warn("ignoring untracked probe result", "worker_id", workerID, "job_id", jobID)
		return
	}
	req := probeCompleteRequest(workerID, jobID, pr)
	if _, err := d.leasing.Complete(ctx, req); err != nil {
		// Stale revision / invalid lease / validation failure: the slot is already
		// freed above; the DB lease governs whether the job is retried.
		slog.Warn("probe completion rejected", "worker_id", workerID, "job_id", jobID, "err", err)
	}
}

// Run drives the retry sweep until ctx is cancelled. Each tick reclaims expired
// in-flight slots and claims queued jobs to refill the freed capacity.
func (d *ProbeDispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(probeDispatchInterval)
	defer ticker.Stop()
	for {
		d.dispatchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// dispatchOnce reclaims lease-expired slots, then for every worker with free
// capacity claims and pushes up to that many compatible jobs. The dispatcher is the
// sole claimer (single Run goroutine), so a worker's in-flight count only grows
// here and only shrinks via HandleResult/reclaim — the free-slot count computed
// under the lock is a safe claim budget.
func (d *ProbeDispatcher) dispatchOnce(ctx context.Context) {
	type slot struct {
		workerID string
		protocol targetidentity.Protocol
		gen      uint64
		free     int
	}
	now := d.now()
	d.mu.Lock()
	slots := make([]slot, 0, len(d.workers))
	for id, w := range d.workers {
		for job, expiry := range w.inflight {
			if now.After(expiry) {
				delete(w.inflight, job)
			}
		}
		if free := d.maxPerWorker - len(w.inflight); free > 0 {
			slots = append(slots, slot{workerID: id, protocol: w.protocol, gen: w.gen, free: free})
		}
	}
	d.mu.Unlock()

	for _, s := range slots {
		for range s.free {
			lease, err := d.leasing.Claim(ctx, targetidentity.ClaimRequest{WorkerID: s.workerID, Protocol: s.protocol})
			if errors.Is(err, targetidentity.ErrNoProbeAvailable) {
				break
			}
			if err != nil {
				slog.Warn("probe claim failed", "worker_id", s.workerID, "protocol", s.protocol, "err", err)
				break
			}
			assignment, err := d.buildAssignment(lease)
			if err != nil {
				// A malformed endpoint is a warden-side config fault; the lease will
				// expire and the job re-queues. Don't wedge the worker on it.
				slog.Error("probe assignment build failed", "job_id", lease.JobID, "err", err)
				continue
			}
			if !d.enqueue(s.workerID, s.gen, lease.JobID, lease.ExpiresAt, assignment) {
				break // worker gone or reconnected; nothing more to push it
			}
		}
	}
}

// enqueue records an in-flight lease and pushes its assignment to the worker's sink,
// but only if the worker is still present under the same registration generation.
// The sink is buffered to maxPerWorker and in-flight never exceeds that, so the send
// cannot block; a full sink is treated defensively as "worker gone".
func (d *ProbeDispatcher) enqueue(workerID string, gen uint64, jobID uuid.UUID, expiry time.Time, a *dataplanev1.ProbeAssignment) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.workers[workerID]
	if w == nil || w.gen != gen {
		return false
	}
	select {
	case w.sink <- a:
		w.inflight[jobID] = expiry
		return true
	default:
		return false
	}
}

// buildAssignment renders a credential-free ProbeAssignment from a domain lease. It
// carries only public target information plus warden's execution limits — no secret,
// admission token, login, or user identity.
func (d *ProbeDispatcher) buildAssignment(lease targetidentity.ProbeLease) (*dataplanev1.ProbeAssignment, error) {
	a := &dataplanev1.ProbeAssignment{
		JobId:                lease.JobID.String(),
		AssetId:              lease.Endpoint.AssetID.String(),
		EndpointRevision:     lease.Endpoint.EndpointRevision,
		LeaseToken:           lease.Token,
		Protocol:             probeProtocolEnum(lease.Endpoint.Protocol),
		LeaseExpiresAtUnixMs: lease.ExpiresAt.UnixMilli(),
		Limits:               d.limits,
	}
	switch lease.Endpoint.Protocol {
	case targetidentity.ProtocolSSH:
		host, port, err := splitHostPort(lease.Endpoint.TargetAddress)
		if err != nil {
			return nil, err
		}
		a.Endpoint = &dataplanev1.ProbeAssignment_Ssh{Ssh: &dataplanev1.SSHProbeEndpoint{Host: host, Port: port}}
	case targetidentity.ProtocolPostgres:
		host, port, err := splitHostPort(lease.Endpoint.TargetAddress)
		if err != nil {
			return nil, err
		}
		a.Endpoint = &dataplanev1.ProbeAssignment_Postgres{Postgres: &dataplanev1.PostgresProbeEndpoint{Host: host, Port: port}}
	case targetidentity.ProtocolRDP:
		host, port, err := splitHostPort(lease.Endpoint.TargetAddress)
		if err != nil {
			return nil, err
		}
		a.Endpoint = &dataplanev1.ProbeAssignment_Rdp{Rdp: &dataplanev1.RDPProbeEndpoint{Host: host, Port: port}}
	case targetidentity.ProtocolKubernetes:
		a.Endpoint = &dataplanev1.ProbeAssignment_Kubernetes{Kubernetes: &dataplanev1.KubernetesProbeEndpoint{ApiServerName: lease.Endpoint.TargetAddress}}
	default:
		return nil, fmt.Errorf("unsupported probe protocol %q", lease.Endpoint.Protocol)
	}
	return a, nil
}

// splitHostPort splits a "host:port" target address into a host and a validated
// port. The address is warden-provided (asset config), so a parse failure is a
// config fault, not worker input.
func splitHostPort(address string) (string, uint32, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("split target address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid target port in %q", address)
	}
	return host, uint32(port), nil
}

// domainProtocol maps a worker's advertised protocol string to a domain Protocol.
// The wire uses "kubernetes" while the domain (asset kind) uses "k8s"; the rest are
// identity mappings. An unprobeable protocol returns false.
func domainProtocol(protocol string) (targetidentity.Protocol, bool) {
	switch protocol {
	case "ssh":
		return targetidentity.ProtocolSSH, true
	case "postgres":
		return targetidentity.ProtocolPostgres, true
	case "rdp":
		return targetidentity.ProtocolRDP, true
	case "kubernetes", "k8s":
		return targetidentity.ProtocolKubernetes, true
	default:
		return "", false
	}
}

// probeProtocolEnum maps a domain Protocol to its wire enum.
func probeProtocolEnum(p targetidentity.Protocol) dataplanev1.ProbeProtocol {
	switch p {
	case targetidentity.ProtocolSSH:
		return dataplanev1.ProbeProtocol_PROBE_PROTOCOL_SSH
	case targetidentity.ProtocolPostgres:
		return dataplanev1.ProbeProtocol_PROBE_PROTOCOL_POSTGRES
	case targetidentity.ProtocolRDP:
		return dataplanev1.ProbeProtocol_PROBE_PROTOCOL_RDP
	case targetidentity.ProtocolKubernetes:
		return dataplanev1.ProbeProtocol_PROBE_PROTOCOL_KUBERNETES
	default:
		return dataplanev1.ProbeProtocol_PROBE_PROTOCOL_UNSPECIFIED
	}
}

// probeCompleteRequest converts a worker ProbeResult into a domain CompleteRequest.
// The job id is parsed once by the caller; the worker id is authoritative (from the
// mesh stream identity), never the wire.
func probeCompleteRequest(workerID string, jobID uuid.UUID, pr *dataplanev1.ProbeResult) targetidentity.CompleteRequest {
	result := targetidentity.ProbeResult{
		Outcome:           probeOutcome(pr.GetOutcome()),
		ResolvedAddresses: pr.GetResolvedAddresses(),
		FailureCategory:   probeFailureCategory(pr.GetFailureCategory()),
		FailureDetail:     pr.GetFailureDetail(),
	}
	if ms := pr.GetObservedAtUnixMs(); ms > 0 {
		result.ObservedAt = time.UnixMilli(ms).UTC()
	}
	for _, e := range pr.GetEvidence() {
		result.Evidence = append(result.Evidence, probeEvidence(e))
	}
	switch m := pr.GetProtocolMetadata().(type) {
	case *dataplanev1.ProbeResult_Ssh:
		result.SSH = &targetidentity.SSHMetadata{Banner: m.Ssh.GetBanner(), HostKeyAlgorithms: m.Ssh.GetHostKeyAlgorithms()}
	case *dataplanev1.ProbeResult_Tls:
		result.TLS = &targetidentity.TLSMetadata{Version: m.Tls.GetVersion(), CipherSuite: m.Tls.GetCipherSuite(), ServerName: m.Tls.GetServerName(), ALPN: m.Tls.GetAlpn()}
	case *dataplanev1.ProbeResult_Kubernetes:
		result.Kubernetes = &targetidentity.KubernetesMetadata{APIServerName: m.Kubernetes.GetApiServerName()}
	}
	return targetidentity.CompleteRequest{
		JobID:      jobID,
		WorkerID:   workerID,
		LeaseToken: pr.GetLeaseToken(),
		Result:     result,
	}
}

func probeEvidence(e *dataplanev1.ProbeEvidence) targetidentity.Evidence {
	ev := targetidentity.Evidence{
		Kind:               evidenceKind(e.GetKind()),
		Algorithm:          e.GetAlgorithm(),
		Fingerprint:        e.GetSha256Fingerprint(),
		PublicMaterial:     e.GetPublicMaterial(),
		CertificateSubject: e.GetCertificateSubject(),
		CertificateIssuer:  e.GetCertificateIssuer(),
		IssuerFingerprint:  e.GetIssuerSha256Fingerprint(),
		DNSNames:           e.GetDnsNames(),
		IPAddresses:        e.GetIpAddresses(),
		SSHPrincipals:      e.GetSshPrincipals(),
		SerialNumber:       e.GetSerialNumber(),
		Key:                targetidentity.KeyMetadata{Bits: int(e.GetKeyBits()), Curve: e.GetKeyCurve()},
	}
	if ms := e.GetValidFromUnixMs(); ms > 0 {
		ev.ValidFrom = time.UnixMilli(ms).UTC()
	}
	if ms := e.GetValidUntilUnixMs(); ms > 0 {
		ev.ValidUntil = time.UnixMilli(ms).UTC()
	}
	for _, x := range e.GetDisplayExtensions() {
		ev.DisplayExtensions = append(ev.DisplayExtensions, targetidentity.DisplayExtension{Name: x.GetName(), Value: x.GetValue()})
	}
	return ev
}

func probeOutcome(o dataplanev1.ProbeOutcome) targetidentity.ProbeOutcome {
	if o == dataplanev1.ProbeOutcome_PROBE_OUTCOME_SUCCEEDED {
		return targetidentity.ProbeSucceeded
	}
	return targetidentity.ProbeFailed
}

func evidenceKind(k dataplanev1.ProbeEvidenceKind) targetidentity.EvidenceKind {
	switch k {
	case dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_SSH_HOST_KEY:
		return targetidentity.EvidenceSSHHostKey
	case dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_SSH_HOST_CERTIFICATE:
		return targetidentity.EvidenceSSHHostCertificate
	case dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_LEAF:
		return targetidentity.EvidenceTLSLeaf
	case dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_INTERMEDIATE:
		return targetidentity.EvidenceTLSIntermediate
	case dataplanev1.ProbeEvidenceKind_PROBE_EVIDENCE_KIND_TLS_PRESENTED_ROOT:
		return targetidentity.EvidenceTLSPresentedRoot
	default:
		return ""
	}
}

// probeFailureCategory maps a wire failure category to a domain one. The
// dispatcher-only UNSUPPORTED_PROTOCOL (a worker that cannot yet probe its own
// protocol) has no domain equivalent and maps to no_compatible_worker — accurate
// while protocol probing is unimplemented.
func probeFailureCategory(c dataplanev1.ProbeFailureCategory) targetidentity.FailureCategory {
	switch c {
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_UNSUPPORTED_PROTOCOL,
		dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_NO_COMPATIBLE_WORKER:
		return targetidentity.FailureNoCompatibleWorker
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_DNS_RESOLUTION_FAILED:
		return targetidentity.FailureDNSResolution
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CONNECTION_REFUSED:
		return targetidentity.FailureConnectionRefused
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CONNECTION_TIMEOUT:
		return targetidentity.FailureConnectionTimeout
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_PROTOCOL_MISMATCH:
		return targetidentity.FailureProtocolMismatch
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_INSECURE_DOWNGRADE:
		return targetidentity.FailureInsecureDowngrade
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_UNSUPPORTED_IDENTITY_ALGORITHM:
		return targetidentity.FailureUnsupportedIdentityAlgorithm
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_MALFORMED_IDENTITY:
		return targetidentity.FailureMalformedIdentity
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_IDENTITY_TOO_LARGE:
		return targetidentity.FailureIdentityTooLarge
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CERTIFICATE_EXPIRED:
		return targetidentity.FailureCertificateExpired
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_CERTIFICATE_NOT_YET_VALID:
		return targetidentity.FailureCertificateNotYetValid
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_NAME_MISMATCH:
		return targetidentity.FailureNameMismatch
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_EXPECTATION_MISMATCH:
		return targetidentity.FailureExpectationMismatch
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_WORKER_LOST:
		return targetidentity.FailureWorkerLost
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_LEASE_EXPIRED:
		return targetidentity.FailureLeaseExpired
	case dataplanev1.ProbeFailureCategory_PROBE_FAILURE_CATEGORY_TARGET_IDENTITY_CHANGED:
		return targetidentity.FailureTargetIdentityChanged
	default:
		return ""
	}
}
