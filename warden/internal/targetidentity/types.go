// Package targetidentity owns durable target-identity probing and trust state.
// It intentionally exposes domain types rather than protobuf-generated types so
// transports and workers cannot become the source of authorization decisions.
package targetidentity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Public resource bounds applied before any probe result is persisted.
const (
	MaxEvidenceCount        = 16
	MaxPublicMaterialBytes  = 64 << 10
	MaxResolvedAddresses    = 16
	MaxNames                = 64
	MaxNameBytes            = 255
	MaxFailureDetailBytes   = 4096
	MaxMetadataTextBytes    = 4096
	MaxCertificateNameBytes = 4096
	MaxSerialNumberBytes    = 256
	MaxKeyCurveBytes        = 64
	MaxKeyBits              = 16384
	MaxExtensions           = 32
	LeaseTokenBytes         = 32
)

// Stable domain errors allow transport adapters to map failures without
// inspecting error strings.
var (
	ErrInvalidRequest       = errors.New("invalid target identity request")
	ErrInvalidResult        = errors.New("invalid target identity result")
	ErrAssetNotFound        = errors.New("asset not found")
	ErrObservationNotFound  = errors.New("observation not found")
	ErrEvidenceNotFound     = errors.New("selected evidence not found")
	ErrAnchorNotFound       = errors.New("trust anchor not found")
	ErrStaleRevision        = errors.New("stale endpoint revision")
	ErrNoProbeAvailable     = errors.New("no compatible probe available")
	ErrProbeAlreadyQueued   = errors.New("a probe is already queued")
	ErrInvalidLease         = errors.New("invalid or expired probe lease")
	ErrExpectationMismatch  = errors.New("identity expectation mismatch")
	ErrAuditUnavailable     = errors.New("transactional audit unavailable")
	ErrUnsupportedEvidence  = errors.New("evidence cannot be approved as requested")
	ErrValidationFactNeeded = errors.New("CA approval requires an explicit validation fact")
	ErrIdempotencyConflict  = errors.New("request_id is already bound to a different mutation")
)

// Protocol identifies the target protocol a probe worker serves.
type Protocol string

// Supported target protocols.
const (
	ProtocolSSH        Protocol = "ssh"
	ProtocolPostgres   Protocol = "postgres"
	ProtocolRDP        Protocol = "rdp"
	ProtocolKubernetes Protocol = "k8s"
)

// ProbeReason records why a durable probe job was requested.
type ProbeReason string

// Durable probe reasons.
const (
	ProbeReasonOnboarding      ProbeReason = "onboarding"
	ProbeReasonManual          ProbeReason = "manual"
	ProbeReasonPeriodic        ProbeReason = "periodic"
	ProbeReasonEndpointChanged ProbeReason = "endpoint_changed"
	ProbeReasonSessionMismatch ProbeReason = "session_mismatch"
)

// ProbeState is the durable lifecycle state of a probe job.
type ProbeState string

// Durable probe job states.
const (
	ProbeQueued         ProbeState = "queued"
	ProbeLeased         ProbeState = "leased"
	ProbeStateSucceeded ProbeState = "succeeded"
	ProbeStateFailed    ProbeState = "failed"
	ProbeSuperseded     ProbeState = "superseded"
	ProbeCancelled      ProbeState = "cancelled"
)

// ProbeOutcome is the terminal outcome reported by a worker.
type ProbeOutcome string

// Supported worker-reported outcomes.
const (
	ProbeSucceeded ProbeOutcome = "succeeded"
	ProbeFailed    ProbeOutcome = "failed"

	OutcomeSucceeded = ProbeSucceeded
	OutcomeFailed    = ProbeFailed
)

// ObservationSource identifies whether evidence came from a probe or session.
type ObservationSource string

// Supported observation sources.
const (
	ObservationProbe           ObservationSource = "probe"
	ObservationSessionMismatch ObservationSource = "session_mismatch"
)

// EvidenceKind identifies normalized public identity material.
type EvidenceKind string

// Supported evidence kinds.
const (
	EvidenceSSHHostKey         EvidenceKind = "ssh_host_key"
	EvidenceSSHHostCertificate EvidenceKind = "ssh_host_certificate"
	EvidenceTLSLeaf            EvidenceKind = "tls_leaf"
	EvidenceTLSIntermediate    EvidenceKind = "tls_intermediate"
	EvidenceTLSPresentedRoot   EvidenceKind = "tls_presented_root"
)

// TrustAnchorKind identifies the scope of approved target trust.
type TrustAnchorKind string

// Supported trust-anchor kinds.
const (
	AnchorSSHHostKey TrustAnchorKind = "ssh_host_key"
	AnchorSSHHostCA  TrustAnchorKind = "ssh_host_ca"
	AnchorTLSCA      TrustAnchorKind = "tls_ca"
	AnchorTLSLeaf    TrustAnchorKind = "tls_leaf"
)

// TrustSource records how an operator established trust.
type TrustSource string

// Supported trust provenance values.
const (
	TrustSourceManual    TrustSource = "manual"
	TrustSourceExpected  TrustSource = "expected"
	TrustSourceTOFU      TrustSource = "tofu"
	TrustSourceMigration TrustSource = "migration"
)

// FailureCategory is a stable, sanitized probe failure category.
type FailureCategory string

// Stable failure categories exposed to transports and operators.
const (
	FailureNoCompatibleWorker           FailureCategory = "no_compatible_worker"
	FailureDNSResolution                FailureCategory = "dns_resolution_failed"
	FailureConnectionRefused            FailureCategory = "connection_refused"
	FailureConnectionTimeout            FailureCategory = "connection_timeout"
	FailureProtocolMismatch             FailureCategory = "protocol_mismatch"
	FailureInsecureDowngrade            FailureCategory = "insecure_downgrade"
	FailureUnsupportedIdentityAlgorithm FailureCategory = "unsupported_identity_algorithm"
	FailureMalformedIdentity            FailureCategory = "malformed_identity"
	FailureIdentityTooLarge             FailureCategory = "identity_too_large"
	FailureCertificateExpired           FailureCategory = "certificate_expired"
	FailureCertificateNotYetValid       FailureCategory = "certificate_not_yet_valid"
	FailureNameMismatch                 FailureCategory = "name_mismatch"
	FailureExpectationMismatch          FailureCategory = "expectation_mismatch"
	FailureWorkerLost                   FailureCategory = "worker_lost"
	FailureLeaseExpired                 FailureCategory = "lease_expired"
	FailureTargetIdentityChanged        FailureCategory = "target_identity_changed"
)

// VerificationStatus is the user-facing state derived from durable facts.
type VerificationStatus string

// Derived verification states.
const (
	StatusPendingVerification VerificationStatus = "pending_verification"
	StatusProbeFailed         VerificationStatus = "probe_failed"
	StatusAwaitingApproval    VerificationStatus = "awaiting_approval"
	StatusVerified            VerificationStatus = "verified"
	StatusIdentityChanged     VerificationStatus = "identity_changed"
	StatusVerificationExpired VerificationStatus = "verification_expired"
)

// Endpoint is the credential-free target information assigned to a worker.
type Endpoint struct {
	AssetID          uuid.UUID
	EndpointRevision int64
	Protocol         Protocol
	TargetAddress    string
}

// ProbeJob is the durable job summary returned after queueing.
type ProbeJob struct {
	ID               uuid.UUID
	PreviousJobID    uuid.UUID
	AssetID          uuid.UUID
	EndpointRevision int64
	Protocol         Protocol
	State            ProbeState
	Reason           ProbeReason
	AttemptCount     int
	MaxAttempts      int
	NextAttemptAt    time.Time
	CreatedAt        time.Time
	StartedAt        time.Time
	CompletedAt      time.Time
	FailureCategory  FailureCategory
	FailureDetail    string
}

// ProbeLease grants one worker a short-lived attempt against an endpoint.
type ProbeLease struct {
	JobID         uuid.UUID
	AttemptID     uuid.UUID
	Endpoint      Endpoint
	Reason        ProbeReason
	AttemptNumber int
	MaxAttempts   int
	ExpiresAt     time.Time
	Token         []byte
}

// SSHMetadata and TLSMetadata are deliberately bounded, typed protocol data.
// Display-only extension data belongs on Evidence as typed name/value entries.
type SSHMetadata struct {
	Banner            string
	HostKeyAlgorithms []string
}

// TLSMetadata contains bounded metadata from a TLS negotiation.
type TLSMetadata struct {
	Version     string
	CipherSuite string
	ServerName  string
	ALPN        string
}

// KubernetesMetadata contains bounded Kubernetes API-server metadata.
type KubernetesMetadata struct {
	APIServerName string
}

// KeyMetadata contains bounded, display-only public-key properties.
type KeyMetadata struct {
	Bits  int
	Curve string
}

// DisplayExtension is one bounded certificate extension for operator display.
type DisplayExtension struct {
	Name  string
	Value string
}

// Evidence is one immutable normalized identity item from an observation.
type Evidence struct {
	ID                 uuid.UUID
	ObservationID      uuid.UUID
	Kind               EvidenceKind
	Algorithm          string
	Fingerprint        string
	PublicMaterial     string
	CertificateSubject string
	CertificateIssuer  string
	IssuerFingerprint  string
	DNSNames           []string
	IPAddresses        []string
	SSHPrincipals      []string
	SerialNumber       string
	ValidFrom          time.Time
	ValidUntil         time.Time
	Key                KeyMetadata
	DisplayExtensions  []DisplayExtension
	CreatedAt          time.Time
}

// ValidationFact binds an observed leaf fingerprint to an approved CA anchor.
type ValidationFact struct {
	AnchorID            uuid.UUID
	EvidenceKind        EvidenceKind
	EvidenceFingerprint string
}

// ProbeResult is a bounded worker observation with no credentials or secrets.
type ProbeResult struct {
	Outcome           ProbeOutcome
	ObservedAt        time.Time
	ResolvedAddresses []string
	SSH               *SSHMetadata
	TLS               *TLSMetadata
	Kubernetes        *KubernetesMetadata
	Evidence          []Evidence
	ValidationFacts   []ValidationFact
	FailureCategory   FailureCategory
	FailureDetail     string
}

// Observation is the display-safe immutable identity record exposed to the
// management transport. Worker identity and failure detail remain internal.
type Observation struct {
	ID                uuid.UUID
	JobID             uuid.UUID
	AssetID           uuid.UUID
	EndpointRevision  int64
	Source            ObservationSource
	ResolvedAddresses []string
	ObservedAt        time.Time
	Outcome           string
	ValidationState   string
	FailureCategory   FailureCategory
	FailureDetail     string
	Evidence          []Evidence
	SSH               *SSHMetadata
	TLS               *TLSMetadata
	Kubernetes        *KubernetesMetadata
}

// TrustAnchor is an additive, explicitly approved identity constraint.
type TrustAnchor struct {
	ID                    uuid.UUID
	AssetID               uuid.UUID
	EndpointRevision      int64
	Kind                  TrustAnchorKind
	Algorithm             string
	Fingerprint           string
	PublicMaterial        string
	RequiredSSHPrincipals []string
	RequiredDNSNames      []string
	RequiredIPAddresses   []string
	Source                TrustSource
	ObservationID         uuid.UUID
	ApprovedBy            uuid.UUID
	ApprovedAt            time.Time
	NotBefore             time.Time
	ExpiresAt             time.Time
	RevokedAt             time.Time
	RevokedBy             uuid.UUID
	RevocationReason      string
}

// QueueProbeRequest creates a durable probe for an existing endpoint revision.
type QueueProbeRequest struct {
	RequestID        uuid.UUID
	AssetID          uuid.UUID
	EndpointRevision int64
	Reason           ProbeReason
	RequestedBy      uuid.UUID
	PreviousJobID    uuid.UUID
	MaxAttempts      int
	NextAttemptAt    time.Time
}

// ClaimRequest asks for the next job compatible with a worker protocol.
type ClaimRequest struct {
	WorkerID string
	Protocol Protocol
}

// CompleteRequest submits the terminal result for an owned probe lease.
type CompleteRequest struct {
	JobID      uuid.UUID
	WorkerID   string
	LeaseToken []byte
	Result     ProbeResult
}

// ApproveRequest selects exact observed or supplied public material to trust.
type ApproveRequest struct {
	RequestID              uuid.UUID
	AssetID                uuid.UUID
	ExpectedRevision       int64
	ObservationID          uuid.UUID
	EvidenceID             uuid.UUID
	SelectedFingerprint    string
	AnchorKind             TrustAnchorKind
	SuppliedAlgorithm      string
	SuppliedPublicMaterial string
	Source                 TrustSource
	ActorID                uuid.UUID
	RequiredSSHPrincipals  []string
	RequiredDNSNames       []string
	RequiredIPAddresses    []string
	NotBefore              time.Time
	ExpiresAt              time.Time
	// ValidatedEvidenceID is required when approving a CA. It makes the
	// exact leaf-to-anchor path an explicit durable fact rather than inferring
	// trust from an observation-wide flag or a presented root fingerprint.
	ValidatedEvidenceID uuid.UUID
}

// ApproveEvidenceBatchRequest atomically approves exact evidence selected from
// one observation and records one idempotent audit outcome.
type ApproveEvidenceBatchRequest struct {
	RequestID        uuid.UUID
	AssetID          uuid.UUID
	ExpectedRevision int64
	ObservationID    uuid.UUID
	EvidenceIDs      []uuid.UUID
	Source           TrustSource
	ActorID          uuid.UUID
	NotBefore        time.Time
	ExpiresAt        time.Time
}

// RejectObservationRequest explicitly resolves a mismatch as rejected evidence.
type RejectObservationRequest struct {
	RequestID        uuid.UUID
	AssetID          uuid.UUID
	ExpectedRevision int64
	ObservationID    uuid.UUID
	ActorID          uuid.UUID
	Reason           string
}

// RevokeAnchorRequest explicitly ends trust in one additive anchor.
type RevokeAnchorRequest struct {
	RequestID        uuid.UUID
	AssetID          uuid.UUID
	ExpectedRevision int64
	AnchorID         uuid.UUID
	ActorID          uuid.UUID
	Reason           string
}

// PageRequest is a descending timestamp/UUID keyset cursor. Limit is the
// client-visible bound; service queries fetch one additional row for has-more.
type PageRequest struct {
	Limit     int
	AfterTime time.Time
	AfterID   uuid.UUID
}

// StatusRequest controls status derivation and optional freshness policy.
type StatusRequest struct {
	AssetID   uuid.UUID
	Freshness time.Duration
}

// SessionMismatchRequest records bounded evidence from runtime enforcement.
type SessionMismatchRequest struct {
	AssetID           uuid.UUID
	EndpointRevision  int64
	WorkerID          string
	ObservedAt        time.Time
	ResolvedAddresses []string
	SSH               *SSHMetadata
	TLS               *TLSMetadata
	Kubernetes        *KubernetesMetadata
	Evidence          []Evidence
}

// Enqueuer is the transactional audit capability required by the service.
// audit.Logger satisfies it; tests can provide a failing implementation to
// prove that domain writes roll back when their audit event cannot be queued.
type Enqueuer interface {
	Enqueue(context.Context, *sqlc.Queries, audit.Event) error
}
