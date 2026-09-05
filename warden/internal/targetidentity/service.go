package targetidentity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

const (
	defaultLeaseDuration = 30 * time.Second
	defaultMaxAttempts   = 3
	maxProbeAttempts     = 10
)

const (
	eventProbeRequested      = "target_identity.probe_requested"
	eventProbeLeased         = "target_identity.probe_leased"
	eventProbeSucceeded      = "target_identity.probe_succeeded"
	eventProbeFailed         = "target_identity.probe_failed"
	eventObservationAccepted = "target_identity.observation_accepted"
	eventObservationRejected = "target_identity.observation_rejected"
	eventAnchorApproved      = "target_identity.anchor_approved"
	eventAnchorRevoked       = "target_identity.anchor_revoked"
	eventRuntimeMismatch     = "target_identity.runtime_mismatch"
)

// Service owns target probe leases, immutable evidence, trust, and status.
type Service struct {
	pool          *pgxpool.Pool
	audit         Enqueuer
	leaseDuration time.Duration
	now           func() time.Time
}

// Option configures a Service dependency used by deterministic domain logic.
type Option func(*Service)

// WithClock overrides the service clock, primarily for deterministic policy tests.
func WithClock(now func() time.Time) Option {
	return func(service *Service) {
		if now != nil {
			service.now = now
		}
	}
}

// NewService constructs a target-identity domain service.
func NewService(pool *pgxpool.Pool, auditLog Enqueuer, options ...Option) *Service {
	service := &Service{pool: pool, audit: auditLog, leaseDuration: defaultLeaseDuration, now: time.Now}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}

// QueueProbe persists a credential-free job for the current endpoint revision.
func (s *Service) QueueProbe(ctx context.Context, req QueueProbeRequest) (ProbeJob, error) {
	if req.AssetID == uuid.Nil || req.EndpointRevision <= 0 || !validProbeReason(req.Reason) {
		return ProbeJob{}, ErrInvalidRequest
	}
	if req.MaxAttempts == 0 {
		req.MaxAttempts = defaultMaxAttempts
	}
	if req.MaxAttempts < 1 || req.MaxAttempts > maxProbeAttempts {
		return ProbeJob{}, ErrInvalidRequest
	}
	if req.NextAttemptAt.IsZero() {
		req.NextAttemptAt = s.now()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProbeJob{}, fmt.Errorf("begin queue probe: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	asset, err := q.LockTargetIdentityAsset(ctx, req.AssetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ProbeJob{}, ErrAssetNotFound
		}
		return ProbeJob{}, fmt.Errorf("lock asset for probe: %w", err)
	}
	if asset.EndpointRevision != req.EndpointRevision {
		return ProbeJob{}, ErrStaleRevision
	}
	if !validProtocol(Protocol(asset.Kind)) {
		return ProbeJob{}, ErrInvalidRequest
	}
	if req.PreviousJobID != uuid.Nil {
		state, err := q.GetPreviousProbeJobState(ctx, sqlc.GetPreviousProbeJobStateParams{JobID: req.PreviousJobID, AssetID: req.AssetID, EndpointRevision: asset.EndpointRevision})
		if err != nil {
			return ProbeJob{}, ErrInvalidRequest
		}
		if state != "succeeded" && state != "failed" && state != "superseded" && state != "cancelled" {
			return ProbeJob{}, ErrInvalidRequest
		}
	}
	row, err := q.CreateProbeJob(ctx, sqlc.CreateProbeJobParams{
		PreviousJobID:    nullableUUID(req.PreviousJobID),
		AssetID:          req.AssetID,
		EndpointRevision: asset.EndpointRevision,
		Protocol:         asset.Kind,
		Reason:           string(req.Reason),
		RequestedBy:      nullableUUID(req.RequestedBy),
		MaxAttempts:      int32(req.MaxAttempts),
		NextAttemptAt:    pgtype.Timestamptz{Time: req.NextAttemptAt, Valid: true},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return ProbeJob{}, ErrProbeAlreadyQueued
		}
		return ProbeJob{}, fmt.Errorf("create probe job: %w", err)
	}
	if err := s.enqueue(ctx, q, eventProbeRequested, req.RequestedBy, req.AssetID, map[string]any{
		"job_id": row.ID.String(), "endpoint_revision": asset.EndpointRevision, "reason": req.Reason,
	}); err != nil {
		return ProbeJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProbeJob{}, fmt.Errorf("commit queue probe: %w", err)
	}
	return probeJobFromRow(row), nil
}

// Claim leases the next compatible job to a protocol worker.
func (s *Service) Claim(ctx context.Context, req ClaimRequest) (ProbeLease, error) {
	if req.WorkerID == "" || !validProtocol(req.Protocol) {
		return ProbeLease{}, ErrInvalidRequest
	}
	token := make([]byte, LeaseTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return ProbeLease{}, fmt.Errorf("generate lease token: %w", err)
	}
	hash := sha256.Sum256(token)
	expiresAt := s.now().Add(s.leaseDuration)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProbeLease{}, fmt.Errorf("begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	row, err := q.ClaimProbeJobForProtocol(ctx, sqlc.ClaimProbeJobForProtocolParams{
		Protocol: string(req.Protocol), WorkerID: pgtype.Text{String: req.WorkerID, Valid: true},
		LeaseTokenHash: hash[:], LeaseExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ProbeLease{}, ErrNoProbeAvailable
	}
	if err != nil {
		return ProbeLease{}, fmt.Errorf("claim probe: %w", err)
	}
	if err := s.enqueue(ctx, q, eventProbeLeased, uuid.Nil, row.AssetID, map[string]any{
		"job_id": row.JobID.String(), "worker_id": req.WorkerID, "attempt": row.AttemptCount,
	}); err != nil {
		return ProbeLease{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProbeLease{}, fmt.Errorf("commit claim: %w", err)
	}
	return ProbeLease{
		JobID: row.JobID, AttemptID: row.AttemptID,
		Endpoint: Endpoint{AssetID: row.AssetID, EndpointRevision: row.EndpointRevision, Protocol: Protocol(row.Protocol), TargetAddress: row.TargetAddress},
		Reason:   ProbeReason(row.Reason), AttemptNumber: int(row.AttemptCount), MaxAttempts: int(row.MaxAttempts),
		ExpiresAt: row.LeaseExpiresAt.Time, Token: append([]byte(nil), token...),
	}, nil
}

// Complete atomically finishes a lease, persists evidence, and derives status.
func (s *Service) Complete(ctx context.Context, req CompleteRequest) (VerificationStatus, error) {
	now := s.now()
	if req.JobID == uuid.Nil || req.WorkerID == "" || len(req.LeaseToken) != LeaseTokenBytes {
		return "", ErrInvalidRequest
	}
	if err := validateResult(req.Result, now); err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := sqlc.New(tx)
	locked, err := q.LockProbeCompletion(ctx, req.JobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrInvalidLease
		}
		return "", fmt.Errorf("lock probe completion: %w", err)
	}
	if locked.JobEndpointRevision != locked.AssetEndpointRevision {
		return "", ErrStaleRevision
	}
	if err := validateProtocolResult(Protocol(locked.Protocol), req.Result); err != nil {
		return "", err
	}
	assetID := locked.AssetID
	jobRevision := locked.JobEndpointRevision
	anchors, err := q.ListCurrentActiveTrustAnchors(ctx, sqlc.ListCurrentActiveTrustAnchorsParams{AssetID: assetID, AtTime: now})
	if err != nil {
		return "", fmt.Errorf("list anchors for completion: %w", err)
	}
	observationOutcome := string(req.Result.Outcome)
	failureCategory := req.Result.FailureCategory
	if req.Result.Outcome == ProbeSucceeded && len(anchors) > 0 && !resultMatchesAnchors(req.Result, anchors, now) {
		observationOutcome = "mismatch"
		failureCategory = FailureTargetIdentityChanged
	}
	hash := sha256.Sum256(req.LeaseToken)
	_, err = q.CompleteProbeAttempt(ctx, sqlc.CompleteProbeAttemptParams{
		Outcome: string(req.Result.Outcome), FailureCategory: nullableText(string(failureCategory)),
		FailureDetail: nullableText(req.Result.FailureDetail), JobID: req.JobID,
		WorkerID: pgtype.Text{String: req.WorkerID, Valid: true}, LeaseTokenHash: hash[:],
	})
	if errors.Is(err, pgx.ErrNoRows) {
		completedOutcome, dupErr := q.GetCompletedAttemptOutcome(ctx, sqlc.GetCompletedAttemptOutcomeParams{JobID: req.JobID, WorkerID: req.WorkerID, LeaseTokenHash: hash[:]})
		if dupErr == nil && completedOutcome.Valid && completedOutcome.String == string(req.Result.Outcome) {
			// The immutable completed attempt plus the single-use token is the
			// natural idempotency key. No row or audit event is written twice.
			return s.statusAt(ctx, tx, StatusRequest{AssetID: assetID}, now)
		}
		return "", ErrInvalidLease
	}
	if err != nil {
		return "", fmt.Errorf("complete probe attempt: %w", err)
	}

	observedAt := req.Result.ObservedAt
	if observedAt.IsZero() {
		observedAt = now
	}
	observationID, err := s.insertObservation(ctx, tx, observationInsert{
		JobID: nullableUUID(req.JobID), AssetID: assetID, EndpointRevision: jobRevision,
		WorkerID: req.WorkerID, Source: ObservationProbe, Outcome: observationOutcome,
		ObservedAt: observedAt, ResolvedAddresses: req.Result.ResolvedAddresses,
		SSH: req.Result.SSH, TLS: req.Result.TLS, Kubernetes: req.Result.Kubernetes,
		Evidence: req.Result.Evidence, ValidationFacts: req.Result.ValidationFacts,
		FailureCategory: failureCategory, FailureDetail: req.Result.FailureDetail,
	})
	if err != nil {
		return "", err
	}
	event := eventProbeSucceeded
	if req.Result.Outcome == ProbeFailed {
		event = eventProbeFailed
	}
	if err := s.enqueue(ctx, q, event, uuid.Nil, assetID, map[string]any{
		"job_id": req.JobID.String(), "observation_id": observationID.String(), "worker_id": req.WorkerID,
		"failure_category": failureCategory,
	}); err != nil {
		return "", err
	}
	if err := s.enqueue(ctx, q, eventObservationAccepted, uuid.Nil, assetID, map[string]any{
		"job_id": req.JobID.String(), "observation_id": observationID.String(), "outcome": observationOutcome,
	}); err != nil {
		return "", err
	}
	if observationOutcome == "mismatch" {
		if err := s.enqueue(ctx, q, eventRuntimeMismatch, uuid.Nil, assetID, map[string]any{
			"observation_id": observationID.String(), "source": ObservationProbe,
		}); err != nil {
			return "", err
		}
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: assetID}, now)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit probe completion: %w", err)
	}
	return status, nil
}

// Approve additively trusts exact evidence or supplied CA material.
func (s *Service) Approve(ctx context.Context, req ApproveRequest) (TrustAnchor, VerificationStatus, error) {
	now := s.now()
	supplied := req.SuppliedPublicMaterial != "" || req.SuppliedAlgorithm != ""
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.ObservationID == uuid.Nil || (!supplied && (!validFingerprint(req.SelectedFingerprint) || req.EvidenceID == uuid.Nil)) || !validTrustSource(req.Source) || !validNames(req.RequiredSSHPrincipals) || !validNames(req.RequiredDNSNames) || !validIPNames(req.RequiredIPAddresses) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(now) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	if !req.NotBefore.IsZero() && !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(req.NotBefore) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TrustAnchor{}, "", fmt.Errorf("begin approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if err := lockExpectedRevision(ctx, q, req.AssetID, req.ExpectedRevision); err != nil {
		return TrustAnchor{}, "", err
	}
	asset, err := q.GetAsset(ctx, req.AssetID)
	if err != nil {
		return TrustAnchor{}, "", fmt.Errorf("read locked asset: %w", err)
	}
	observationOutcome, err := q.LockTargetIdentityObservation(ctx, sqlc.LockTargetIdentityObservationParams{ObservationID: req.ObservationID, AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TrustAnchor{}, "", ErrObservationNotFound
		}
		return TrustAnchor{}, "", fmt.Errorf("lock observation: %w", err)
	}
	if observationOutcome != "succeeded" && observationOutcome != "mismatch" {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	var (
		anchorKind        TrustAnchorKind
		anchorAlgorithm   string
		anchorMaterial    string
		anchorFingerprint string
	)
	if supplied {
		if (req.AnchorKind != AnchorTLSCA && req.AnchorKind != AnchorSSHHostCA) || len(req.SuppliedPublicMaterial) == 0 || len(req.SuppliedPublicMaterial) > MaxPublicMaterialBytes || !utf8.ValidString(req.SuppliedPublicMaterial) {
			return TrustAnchor{}, "", ErrInvalidRequest
		}
		anchorKind = req.AnchorKind
		anchorAlgorithm, anchorFingerprint, anchorMaterial, err = normalizeSuppliedCA(anchorKind, req.SuppliedPublicMaterial)
		if err != nil || (req.SuppliedAlgorithm != "" && req.SuppliedAlgorithm != anchorAlgorithm) {
			return TrustAnchor{}, "", ErrInvalidRequest
		}
	} else {
		evidence, err := getEvidenceForApproval(ctx, tx, req.ObservationID, req.EvidenceID)
		if err != nil {
			return TrustAnchor{}, "", err
		}
		if evidence.Fingerprint != req.SelectedFingerprint {
			return TrustAnchor{}, "", ErrEvidenceNotFound
		}
		anchorKind, err = approvalKind(evidence.Kind, req.AnchorKind)
		if err != nil {
			return TrustAnchor{}, "", err
		}
		if (anchorKind == AnchorTLSLeaf || anchorKind == AnchorTLSCA || anchorKind == AnchorSSHHostCA) && !certificateCurrent(evidence, now) {
			return TrustAnchor{}, "", ErrUnsupportedEvidence
		}
		anchorAlgorithm, anchorFingerprint, anchorMaterial = evidence.Algorithm, evidence.Fingerprint, evidence.PublicMaterial
	}
	if !anchorCompatibleWithProtocol(Protocol(asset.Kind), anchorKind) {
		return TrustAnchor{}, "", ErrUnsupportedEvidence
	}
	if (anchorKind == AnchorTLSCA || anchorKind == AnchorSSHHostCA) && req.ValidatedEvidenceID == uuid.Nil {
		return TrustAnchor{}, "", ErrValidationFactNeeded
	}
	row, err := q.ApproveTrustAnchor(ctx, sqlc.ApproveTrustAnchorParams{
		AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision, Kind: string(anchorKind),
		Algorithm: anchorAlgorithm, Sha256Fingerprint: anchorFingerprint, PublicMaterial: anchorMaterial,
		RequiredSshPrincipals: cloneStrings(req.RequiredSSHPrincipals), RequiredDnsNames: cloneStrings(req.RequiredDNSNames), RequiredIpAddresses: cloneStrings(req.RequiredIPAddresses),
		Source: string(req.Source), ObservationID: nullableUUID(req.ObservationID), ApprovedBy: nullableUUID(req.ActorID),
		ApprovedAt: pgtype.Timestamptz{Time: now, Valid: true}, NotBefore: nullableTime(req.NotBefore), ExpiresAt: nullableTime(req.ExpiresAt),
	})
	if err != nil {
		return TrustAnchor{}, "", fmt.Errorf("approve trust anchor: %w", err)
	}
	if anchorKind == AnchorTLSCA || anchorKind == AnchorSSHHostCA {
		leaf, err := q.GetValidationEvidence(ctx, sqlc.GetValidationEvidenceParams{EvidenceID: req.ValidatedEvidenceID, ObservationID: req.ObservationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return TrustAnchor{}, "", ErrValidationFactNeeded
		}
		if err != nil {
			return TrustAnchor{}, "", fmt.Errorf("read approval validation evidence: %w", err)
		}
		if (anchorKind == AnchorTLSCA && leaf.Kind != string(EvidenceTLSLeaf)) || (anchorKind == AnchorSSHHostCA && leaf.Kind != string(EvidenceSSHHostCertificate)) {
			return TrustAnchor{}, "", ErrValidationFactNeeded
		}
		if !leaf.ValidFrom.Valid || !leaf.ValidUntil.Valid || leaf.ValidFrom.Time.After(now) || !leaf.ValidUntil.Time.After(now) {
			return TrustAnchor{}, "", ErrValidationFactNeeded
		}
		if err := q.InsertIdentityValidationFact(ctx, sqlc.InsertIdentityValidationFactParams{ObservationID: req.ObservationID, AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision, AnchorID: row.ID, EvidenceID: req.ValidatedEvidenceID}); err != nil {
			return TrustAnchor{}, "", fmt.Errorf("record approval validation fact: %w", err)
		}
	}
	if err := s.enqueue(ctx, q, eventAnchorApproved, req.ActorID, req.AssetID, map[string]any{
		"anchor_id": row.ID.String(), "observation_id": req.ObservationID.String(), "fingerprint": anchorFingerprint,
		"kind": anchorKind, "source": req.Source, "resolved_identity_change": observationOutcome == "mismatch",
	}); err != nil {
		return TrustAnchor{}, "", err
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, now)
	if err != nil {
		return TrustAnchor{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return TrustAnchor{}, "", fmt.Errorf("commit approval: %w", err)
	}
	return trustAnchorFromRow(row), status, nil
}

// RejectObservation explicitly resolves one current-revision mismatch.
func (s *Service) RejectObservation(ctx context.Context, req RejectObservationRequest) (VerificationStatus, error) {
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.ObservationID == uuid.Nil || len(req.Reason) > 500 || !utf8.ValidString(req.Reason) {
		return "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin rejection: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if err := lockExpectedRevision(ctx, q, req.AssetID, req.ExpectedRevision); err != nil {
		return "", err
	}
	outcome, err := q.LockTargetIdentityObservation(ctx, sqlc.LockTargetIdentityObservationParams{ObservationID: req.ObservationID, AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrObservationNotFound
		}
		return "", fmt.Errorf("lock rejected observation: %w", err)
	}
	if outcome != "mismatch" {
		return "", ErrInvalidRequest
	}
	if err := s.enqueue(ctx, q, eventObservationRejected, req.ActorID, req.AssetID, map[string]any{
		"observation_id": req.ObservationID.String(), "reason": req.Reason,
	}); err != nil {
		return "", err
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, s.now())
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit observation rejection: %w", err)
	}
	return status, nil
}

// RevokeAnchor revokes one anchor without modifying overlapping anchors.
func (s *Service) RevokeAnchor(ctx context.Context, req RevokeAnchorRequest) (VerificationStatus, error) {
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.AnchorID == uuid.Nil || len(req.Reason) > 500 || !utf8.ValidString(req.Reason) {
		return "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if err := lockExpectedRevision(ctx, q, req.AssetID, req.ExpectedRevision); err != nil {
		return "", err
	}
	row, err := q.RevokeTrustAnchor(ctx, sqlc.RevokeTrustAnchorParams{
		RevokedAt: pgtype.Timestamptz{Time: s.now(), Valid: true}, RevokedBy: nullableUUID(req.ActorID),
		RevocationReason: nullableText(req.Reason), AnchorID: req.AnchorID, AssetID: req.AssetID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAnchorNotFound
	}
	if err != nil {
		return "", fmt.Errorf("revoke trust anchor: %w", err)
	}
	if row.EndpointRevision != req.ExpectedRevision {
		return "", ErrStaleRevision
	}
	if err := s.enqueue(ctx, q, eventAnchorRevoked, req.ActorID, req.AssetID, map[string]any{
		"anchor_id": req.AnchorID.String(), "reason": req.Reason,
	}); err != nil {
		return "", err
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, s.now())
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit revocation: %w", err)
	}
	return status, nil
}

// RecordSessionMismatch durably blocks new sessions after runtime mismatch.
func (s *Service) RecordSessionMismatch(ctx context.Context, req SessionMismatchRequest) (VerificationStatus, error) {
	result := ProbeResult{Outcome: ProbeSucceeded, ObservedAt: req.ObservedAt, ResolvedAddresses: req.ResolvedAddresses, SSH: req.SSH, TLS: req.TLS, Kubernetes: req.Kubernetes, Evidence: req.Evidence}
	if req.AssetID == uuid.Nil || req.EndpointRevision <= 0 || req.WorkerID == "" {
		return "", ErrInvalidRequest
	}
	if err := validateResult(result, s.now()); err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin mismatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if err := lockExpectedRevision(ctx, q, req.AssetID, req.EndpointRevision); err != nil {
		return "", err
	}
	observedAt := req.ObservedAt
	if observedAt.IsZero() {
		observedAt = s.now()
	}
	observationID, err := s.insertObservation(ctx, tx, observationInsert{
		AssetID: req.AssetID, EndpointRevision: req.EndpointRevision, WorkerID: req.WorkerID,
		Source: ObservationSessionMismatch, Outcome: "mismatch", ObservedAt: observedAt,
		ResolvedAddresses: req.ResolvedAddresses, SSH: req.SSH, TLS: req.TLS, Kubernetes: req.Kubernetes,
		Evidence: req.Evidence, FailureCategory: FailureTargetIdentityChanged,
	})
	if err != nil {
		return "", err
	}
	if err := s.enqueue(ctx, q, eventRuntimeMismatch, uuid.Nil, req.AssetID, map[string]any{
		"observation_id": observationID.String(), "worker_id": req.WorkerID, "source": ObservationSessionMismatch,
	}); err != nil {
		return "", err
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, s.now())
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit mismatch: %w", err)
	}
	return status, nil
}

// ListEvidence returns immutable evidence for one asset endpoint revision.
func (s *Service) ListEvidence(ctx context.Context, assetID uuid.UUID, endpointRevision int64) ([]Evidence, error) {
	if assetID == uuid.Nil || endpointRevision <= 0 {
		return nil, ErrInvalidRequest
	}
	return listEvidence(ctx, s.pool, assetID, endpointRevision)
}

// ListAnchors returns active, future, expired, and revoked anchor history.
func (s *Service) ListAnchors(ctx context.Context, assetID uuid.UUID) ([]TrustAnchor, error) {
	if assetID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	rows, err := sqlc.New(s.pool).ListTrustAnchors(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("list trust anchors: %w", err)
	}
	out := make([]TrustAnchor, 0, len(rows))
	for _, row := range rows {
		out = append(out, trustAnchorFromRow(row))
	}
	return out, nil
}

type observationInsert struct {
	JobID             pgtype.UUID
	AssetID           uuid.UUID
	EndpointRevision  int64
	WorkerID          string
	Source            ObservationSource
	Outcome           string
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

type protocolMetadata struct {
	SSH        *SSHMetadata        `json:"ssh,omitempty"`
	TLS        *TLSMetadata        `json:"tls,omitempty"`
	Kubernetes *KubernetesMetadata `json:"kubernetes,omitempty"`
}

func (s *Service) insertObservation(ctx context.Context, tx pgx.Tx, in observationInsert) (uuid.UUID, error) {
	addresses, err := json.Marshal(cloneStrings(in.ResolvedAddresses))
	if err != nil {
		return uuid.Nil, ErrInvalidResult
	}
	metadata, err := json.Marshal(protocolMetadata{SSH: in.SSH, TLS: in.TLS, Kubernetes: in.Kubernetes})
	if err != nil {
		return uuid.Nil, ErrInvalidResult
	}
	validationState := "unvalidated"
	if len(in.ValidationFacts) > 0 {
		validationState = "validated"
	}
	q := sqlc.New(tx)
	observation, err := q.InsertIdentityObservation(ctx, sqlc.InsertIdentityObservationParams{
		JobID: in.JobID, AssetID: in.AssetID, EndpointRevision: in.EndpointRevision,
		WorkerID: in.WorkerID, Source: string(in.Source), ResolvedAddresses: addresses, ProtocolMetadata: metadata,
		ObservedAt: pgtype.Timestamptz{Time: in.ObservedAt, Valid: true}, Outcome: in.Outcome, ValidationState: validationState,
		FailureCategory: nullableText(string(in.FailureCategory)), FailureDetail: nullableText(in.FailureDetail),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert identity observation: %w", err)
	}
	type evidenceKey struct {
		kind        EvidenceKind
		fingerprint string
	}
	evidenceByKey := make(map[evidenceKey]uuid.UUID, len(in.Evidence))
	for _, item := range in.Evidence {
		keyMetadata, _ := json.Marshal(item.Key)
		extensions := make(map[string]string, len(item.DisplayExtensions))
		for _, extension := range item.DisplayExtensions {
			extensions[extension.Name] = extension.Value
		}
		displayExtensions, _ := json.Marshal(extensions)
		row, err := q.InsertIdentityEvidence(ctx, sqlc.InsertIdentityEvidenceParams{
			ObservationID: observation.ID, Kind: string(item.Kind), Algorithm: item.Algorithm,
			Sha256Fingerprint: item.Fingerprint, PublicMaterial: item.PublicMaterial,
			CertificateSubject: nullableText(item.CertificateSubject), CertificateIssuer: nullableText(item.CertificateIssuer),
			IssuerSha256Fingerprint: nullableText(item.IssuerFingerprint), DnsNames: cloneStrings(item.DNSNames),
			IpAddresses: cloneStrings(item.IPAddresses), SshPrincipals: cloneStrings(item.SSHPrincipals),
			SerialNumber: nullableText(item.SerialNumber), ValidFrom: nullableTime(item.ValidFrom), ValidUntil: nullableTime(item.ValidUntil),
			KeyMetadata: keyMetadata, DisplayExtensions: displayExtensions,
		})
		if err != nil {
			return uuid.Nil, fmt.Errorf("insert identity evidence: %w", err)
		}
		evidenceByKey[evidenceKey{kind: item.Kind, fingerprint: item.Fingerprint}] = row.ID
	}
	for _, fact := range in.ValidationFacts {
		evidenceID, ok := evidenceByKey[evidenceKey{kind: fact.EvidenceKind, fingerprint: fact.EvidenceFingerprint}]
		if !ok {
			return uuid.Nil, ErrInvalidResult
		}
		if err := q.InsertIdentityValidationFact(ctx, sqlc.InsertIdentityValidationFactParams{ObservationID: observation.ID, AssetID: in.AssetID, EndpointRevision: in.EndpointRevision, AnchorID: fact.AnchorID, EvidenceID: evidenceID}); err != nil {
			return uuid.Nil, fmt.Errorf("insert identity validation fact: %w", err)
		}
	}
	return observation.ID, nil
}

func listEvidence(ctx context.Context, db sqlc.DBTX, assetID uuid.UUID, revision int64) ([]Evidence, error) {
	rows, err := sqlc.New(db).ListIdentityEvidence(ctx, sqlc.ListIdentityEvidenceParams{AssetID: assetID, EndpointRevision: revision})
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	out := make([]Evidence, 0, len(rows))
	for _, row := range rows {
		out = append(out, evidenceFromRow(row))
	}
	return out, nil
}

func getEvidenceForApproval(ctx context.Context, db sqlc.DBTX, observationID, evidenceID uuid.UUID) (Evidence, error) {
	row, err := sqlc.New(db).GetIdentityEvidenceForApproval(ctx, sqlc.GetIdentityEvidenceForApprovalParams{ObservationID: observationID, EvidenceID: evidenceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Evidence{}, ErrEvidenceNotFound
	}
	if err != nil {
		return Evidence{}, fmt.Errorf("select approval evidence: %w", err)
	}
	return evidenceFromRow(row), nil
}

func validateResult(result ProbeResult, now time.Time) error {
	if result.Outcome != ProbeSucceeded && result.Outcome != ProbeFailed {
		return ErrInvalidResult
	}
	if len(result.ResolvedAddresses) > MaxResolvedAddresses || len(result.Evidence) > MaxEvidenceCount || len(result.FailureDetail) > MaxFailureDetailBytes || !utf8.ValidString(result.FailureDetail) {
		return ErrInvalidResult
	}
	if result.Outcome == ProbeSucceeded && (len(result.Evidence) == 0 || result.FailureCategory != "") {
		return ErrInvalidResult
	}
	if result.Outcome == ProbeFailed && !validFailureCategory(result.FailureCategory) {
		return ErrInvalidResult
	}
	for _, address := range result.ResolvedAddresses {
		if net.ParseIP(address) == nil {
			return ErrInvalidResult
		}
	}
	if !validMetadata(result) {
		return ErrInvalidResult
	}
	seen := make(map[string]struct{}, len(result.Evidence))
	for _, item := range result.Evidence {
		if !validEvidence(item, now) {
			return ErrInvalidResult
		}
		key := string(item.Kind) + "\x00" + item.Fingerprint
		if _, exists := seen[key]; exists {
			return ErrInvalidResult
		}
		seen[key] = struct{}{}
	}
	if len(result.ValidationFacts) > MaxEvidenceCount {
		return ErrInvalidResult
	}
	for _, fact := range result.ValidationFacts {
		if fact.AnchorID == uuid.Nil || !validEvidenceKind(fact.EvidenceKind) || !validFingerprint(fact.EvidenceFingerprint) {
			return ErrInvalidResult
		}
	}
	return nil
}

func validEvidence(item Evidence, _ time.Time) bool {
	if !validEvidenceKind(item.Kind) || item.Algorithm == "" || len(item.Algorithm) > MaxNameBytes || !utf8.ValidString(item.Algorithm) || !validFingerprint(item.Fingerprint) || len(item.PublicMaterial) == 0 || len(item.PublicMaterial) > MaxPublicMaterialBytes || !utf8.ValidString(item.PublicMaterial) {
		return false
	}
	if !validNames(item.DNSNames) || !validIPNames(item.IPAddresses) || !validNames(item.SSHPrincipals) || len(item.DisplayExtensions) > MaxExtensions {
		return false
	}
	if len(item.CertificateSubject) > MaxCertificateNameBytes || len(item.CertificateIssuer) > MaxCertificateNameBytes || len(item.SerialNumber) > MaxSerialNumberBytes || len(item.Key.Curve) > MaxKeyCurveBytes || item.Key.Bits < 0 || item.Key.Bits > MaxKeyBits || !utf8.ValidString(item.CertificateSubject+item.CertificateIssuer+item.SerialNumber+item.Key.Curve) || (item.IssuerFingerprint != "" && !validFingerprint(item.IssuerFingerprint)) {
		return false
	}
	for _, extension := range item.DisplayExtensions {
		if extension.Name == "" || len(extension.Name) > MaxNameBytes || len(extension.Value) > MaxMetadataTextBytes || !utf8.ValidString(extension.Name+extension.Value) {
			return false
		}
	}
	for i, extension := range item.DisplayExtensions {
		for _, previous := range item.DisplayExtensions[:i] {
			if extension.Name == previous.Name {
				return false
			}
		}
	}
	if item.Kind != EvidenceSSHHostKey {
		if item.ValidFrom.IsZero() || item.ValidUntil.IsZero() || !item.ValidUntil.After(item.ValidFrom) {
			return false
		}
	}
	return true
}

func validateProtocolResult(protocol Protocol, result ProbeResult) error {
	if result.Outcome != ProbeSucceeded {
		return nil
	}
	for _, evidence := range result.Evidence {
		switch protocol {
		case ProtocolSSH:
			if result.TLS != nil || result.Kubernetes != nil || (evidence.Kind != EvidenceSSHHostKey && evidence.Kind != EvidenceSSHHostCertificate) {
				return ErrInvalidResult
			}
		case ProtocolPostgres, ProtocolRDP, ProtocolKubernetes:
			if result.SSH != nil || result.Kubernetes != nil || (evidence.Kind != EvidenceTLSLeaf && evidence.Kind != EvidenceTLSIntermediate && evidence.Kind != EvidenceTLSPresentedRoot) {
				return ErrInvalidResult
			}
		default:
			return ErrInvalidResult
		}
	}
	return nil
}

func anchorCompatibleWithProtocol(protocol Protocol, kind TrustAnchorKind) bool {
	switch protocol {
	case ProtocolSSH:
		return kind == AnchorSSHHostKey || kind == AnchorSSHHostCA
	case ProtocolPostgres, ProtocolRDP, ProtocolKubernetes:
		return kind == AnchorTLSLeaf || kind == AnchorTLSCA
	default:
		return false
	}
}

func normalizeSuppliedCA(kind TrustAnchorKind, material string) (string, string, string, error) {
	switch kind {
	case AnchorTLSCA:
		block, rest := pem.Decode([]byte(material))
		if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
			return "", "", "", ErrInvalidRequest
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return "", "", "", ErrInvalidRequest
		}
		sum := sha256.Sum256(block.Bytes)
		return "x509", "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), material, nil
	case AnchorSSHHostCA:
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(material))
		if err != nil {
			return "", "", "", ErrInvalidRequest
		}
		return key.Type(), ssh.FingerprintSHA256(key), material, nil
	default:
		return "", "", "", ErrInvalidRequest
	}
}

func validMetadata(result ProbeResult) bool {
	count := 0
	if result.SSH != nil {
		count++
		if len(result.SSH.Banner) > MaxMetadataTextBytes || !utf8.ValidString(result.SSH.Banner) || !validNames(result.SSH.HostKeyAlgorithms) {
			return false
		}
	}
	if result.TLS != nil {
		count++
		for _, value := range []string{result.TLS.Version, result.TLS.CipherSuite, result.TLS.ServerName, result.TLS.ALPN} {
			if len(value) > MaxNameBytes || !utf8.ValidString(value) {
				return false
			}
		}
	}
	if result.Kubernetes != nil {
		count++
		if len(result.Kubernetes.APIServerName) > MaxNameBytes || !utf8.ValidString(result.Kubernetes.APIServerName) {
			return false
		}
	}
	return count <= 1
}

func validFingerprint(fingerprint string) bool {
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return false
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, prefix))
	return err == nil && len(raw) == sha256.Size && prefix+base64.RawStdEncoding.EncodeToString(raw) == fingerprint
}

func validNames(values []string) bool {
	if len(values) > MaxNames {
		return false
	}
	for _, value := range values {
		if value == "" || len(value) > MaxNameBytes || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

func validIPNames(values []string) bool {
	if !validNames(values) {
		return false
	}
	for _, value := range values {
		if net.ParseIP(value) == nil {
			return false
		}
	}
	return true
}

func (s *Service) enqueue(ctx context.Context, q *sqlc.Queries, eventType string, actorID, assetID uuid.UUID, details map[string]any) error {
	if s.audit == nil {
		return ErrAuditUnavailable
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	if err := s.audit.Enqueue(ctx, q, audit.Event{Type: eventType, ActorID: actorID, Subject: "asset:" + assetID.String(), Details: raw}); err != nil {
		return fmt.Errorf("enqueue %s audit: %w", eventType, err)
	}
	return nil
}

func lockExpectedRevision(ctx context.Context, q *sqlc.Queries, assetID uuid.UUID, expected int64) error {
	asset, err := q.LockTargetIdentityAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAssetNotFound
		}
		return fmt.Errorf("lock asset: %w", err)
	}
	if asset.EndpointRevision != expected {
		return ErrStaleRevision
	}
	return nil
}

func approvalKind(evidenceKind EvidenceKind, requested TrustAnchorKind) (TrustAnchorKind, error) {
	derived := TrustAnchorKind("")
	switch evidenceKind {
	case EvidenceSSHHostKey:
		derived = AnchorSSHHostKey
	case EvidenceTLSLeaf:
		derived = AnchorTLSLeaf
	case EvidenceTLSIntermediate, EvidenceTLSPresentedRoot:
		derived = AnchorTLSCA
	default:
		return "", ErrUnsupportedEvidence
	}
	if requested != "" && requested != derived {
		return "", ErrUnsupportedEvidence
	}
	return derived, nil
}

func validProtocol(value Protocol) bool {
	return value == ProtocolSSH || value == ProtocolPostgres || value == ProtocolRDP || value == ProtocolKubernetes
}

func validProbeReason(value ProbeReason) bool {
	return value == ProbeReasonOnboarding || value == ProbeReasonManual || value == ProbeReasonPeriodic || value == ProbeReasonEndpointChanged || value == ProbeReasonSessionMismatch
}

func validTrustSource(value TrustSource) bool {
	return value == TrustSourceManual || value == TrustSourceExpected || value == TrustSourceTOFU || value == TrustSourceMigration
}

func validEvidenceKind(value EvidenceKind) bool {
	return value == EvidenceSSHHostKey || value == EvidenceSSHHostCertificate || value == EvidenceTLSLeaf || value == EvidenceTLSIntermediate || value == EvidenceTLSPresentedRoot
}

func validFailureCategory(value FailureCategory) bool {
	switch value {
	case FailureNoCompatibleWorker, FailureDNSResolution, FailureConnectionRefused, FailureConnectionTimeout,
		FailureProtocolMismatch, FailureInsecureDowngrade, FailureUnsupportedIdentityAlgorithm,
		FailureMalformedIdentity, FailureIdentityTooLarge, FailureCertificateExpired,
		FailureCertificateNotYetValid, FailureNameMismatch, FailureExpectationMismatch,
		FailureWorkerLost, FailureLeaseExpired, FailureTargetIdentityChanged:
		return true
	default:
		return false
	}
}

func nullableUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: value, Valid: value != uuid.Nil}
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func nullableTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: !value.IsZero()}
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func probeJobFromRow(row sqlc.TargetProbeJob) ProbeJob {
	return ProbeJob{ID: row.ID, PreviousJobID: uuidFromPG(row.PreviousJobID), AssetID: row.AssetID,
		EndpointRevision: row.EndpointRevision, Protocol: Protocol(row.Protocol), State: ProbeState(row.State),
		Reason: ProbeReason(row.Reason), AttemptCount: int(row.AttemptCount), MaxAttempts: int(row.MaxAttempts),
		NextAttemptAt: row.NextAttemptAt, CreatedAt: row.CreatedAt}
}

func evidenceFromRow(row sqlc.TargetIdentityEvidence) Evidence {
	var key KeyMetadata
	var extensionMap map[string]string
	_ = json.Unmarshal(row.KeyMetadata, &key)
	_ = json.Unmarshal(row.DisplayExtensions, &extensionMap)
	extensionNames := make([]string, 0, len(extensionMap))
	for name := range extensionMap {
		extensionNames = append(extensionNames, name)
	}
	sort.Strings(extensionNames)
	extensions := make([]DisplayExtension, 0, len(extensionNames))
	for _, name := range extensionNames {
		extensions = append(extensions, DisplayExtension{Name: name, Value: extensionMap[name]})
	}
	return Evidence{ID: row.ID, ObservationID: row.ObservationID, Kind: EvidenceKind(row.Kind), Algorithm: row.Algorithm,
		Fingerprint: row.Sha256Fingerprint, PublicMaterial: row.PublicMaterial,
		CertificateSubject: textFromPG(row.CertificateSubject), CertificateIssuer: textFromPG(row.CertificateIssuer),
		IssuerFingerprint: textFromPG(row.IssuerSha256Fingerprint), DNSNames: cloneStrings(row.DnsNames),
		IPAddresses: cloneStrings(row.IpAddresses), SSHPrincipals: cloneStrings(row.SshPrincipals), SerialNumber: textFromPG(row.SerialNumber),
		ValidFrom: timeFromPG(row.ValidFrom), ValidUntil: timeFromPG(row.ValidUntil), Key: key, DisplayExtensions: extensions, CreatedAt: row.CreatedAt}
}

func trustAnchorFromRow(row sqlc.TargetTrustAnchor) TrustAnchor {
	return TrustAnchor{ID: row.ID, AssetID: row.AssetID, EndpointRevision: row.EndpointRevision, Kind: TrustAnchorKind(row.Kind),
		Algorithm: row.Algorithm, Fingerprint: row.Sha256Fingerprint, PublicMaterial: row.PublicMaterial,
		RequiredSSHPrincipals: cloneStrings(row.RequiredSshPrincipals), RequiredDNSNames: cloneStrings(row.RequiredDnsNames), RequiredIPAddresses: cloneStrings(row.RequiredIpAddresses),
		Source: TrustSource(row.Source), ObservationID: uuidFromPG(row.ObservationID), ApprovedBy: uuidFromPG(row.ApprovedBy), ApprovedAt: row.ApprovedAt,
		NotBefore: timeFromPG(row.NotBefore), ExpiresAt: timeFromPG(row.ExpiresAt), RevokedAt: timeFromPG(row.RevokedAt), RevokedBy: uuidFromPG(row.RevokedBy), RevocationReason: textFromPG(row.RevocationReason)}
}

func uuidFromPG(value pgtype.UUID) uuid.UUID {
	if !value.Valid {
		return uuid.Nil
	}
	return uuid.UUID(value.Bytes)
}

func textFromPG(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func timeFromPG(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
