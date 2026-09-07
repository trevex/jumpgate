package targetidentity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

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
	idempotencyPayload := req
	idempotencyPayload.RequestID = uuid.Nil
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
	var replay ProbeJob
	replayed, err := claimMutation(ctx, q, req.RequestID, "start_probe", req.AssetID, req.RequestedBy, idempotencyPayload, &replay)
	if err != nil {
		return ProbeJob{}, err
	}
	if replayed {
		return replay, nil
	}
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
		if errors.Is(err, pgx.ErrNoRows) {
			return ProbeJob{}, ErrInvalidRequest
		}
		if err != nil {
			return ProbeJob{}, fmt.Errorf("get previous probe job state: %w", err)
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
	result := probeJobFromRow(row)
	if err := completeMutation(ctx, q, req.RequestID, result); err != nil {
		return ProbeJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProbeJob{}, fmt.Errorf("commit queue probe: %w", err)
	}
	return result, nil
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
	idempotencyPayload := req
	idempotencyPayload.RequestID = uuid.Nil
	now := s.now()
	supplied := req.SuppliedPublicMaterial != "" || req.SuppliedAlgorithm != ""
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.ObservationID == uuid.Nil || (!supplied && (!validFingerprint(req.SelectedFingerprint) || req.EvidenceID == uuid.Nil)) || !validTrustSource(req.Source) || !validNames(req.RequiredSSHPrincipals) || !validNames(req.RequiredDNSNames) || !validIPNames(req.RequiredIPAddresses) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TrustAnchor{}, "", fmt.Errorf("begin approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	var replay approvalMutationResponse
	replayed, err := claimMutation(ctx, q, req.RequestID, "approve_ca", req.AssetID, req.ActorID, idempotencyPayload, &replay)
	if err != nil {
		return TrustAnchor{}, "", err
	}
	if replayed {
		return replay.Anchor, replay.Status, nil
	}
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(now) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
	if !req.NotBefore.IsZero() && !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(req.NotBefore) {
		return TrustAnchor{}, "", ErrInvalidRequest
	}
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
	result := trustAnchorFromRow(row)
	if err := completeMutation(ctx, q, req.RequestID, approvalMutationResponse{Anchor: result, Status: status}); err != nil {
		return TrustAnchor{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return TrustAnchor{}, "", fmt.Errorf("commit approval: %w", err)
	}
	return result, status, nil
}

// ApproveEvidenceBatch atomically approves exact evidence from one observation.
// Validation of every selected item precedes inserts; one audit event records the
// complete logical outcome.
func (s *Service) ApproveEvidenceBatch(ctx context.Context, req ApproveEvidenceBatchRequest) ([]TrustAnchor, VerificationStatus, error) {
	now := s.now()
	idempotencyPayload := req
	idempotencyPayload.RequestID = uuid.Nil
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.ObservationID == uuid.Nil || len(req.EvidenceIDs) < 1 || len(req.EvidenceIDs) > MaxEvidenceCount || !validTrustSource(req.Source) {
		return nil, "", ErrInvalidRequest
	}
	seen := make(map[uuid.UUID]struct{}, len(req.EvidenceIDs))
	for _, id := range req.EvidenceIDs {
		if id == uuid.Nil {
			return nil, "", ErrInvalidRequest
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, "", ErrInvalidRequest
		}
		seen[id] = struct{}{}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("begin evidence approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	var replay batchApprovalMutationResponse
	replayed, err := claimMutation(ctx, q, req.RequestID, "approve_evidence", req.AssetID, req.ActorID, idempotencyPayload, &replay)
	if err != nil {
		return nil, "", err
	}
	if replayed {
		return replay.Anchors, replay.Status, nil
	}
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(now) {
		return nil, "", ErrInvalidRequest
	}
	if !req.NotBefore.IsZero() && !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(req.NotBefore) {
		return nil, "", ErrInvalidRequest
	}
	if err := lockExpectedRevision(ctx, q, req.AssetID, req.ExpectedRevision); err != nil {
		return nil, "", err
	}
	asset, err := q.GetAsset(ctx, req.AssetID)
	if err != nil {
		return nil, "", fmt.Errorf("read locked asset: %w", err)
	}
	observationOutcome, err := q.LockTargetIdentityObservation(ctx, sqlc.LockTargetIdentityObservationParams{ObservationID: req.ObservationID, AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrObservationNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("lock observation for evidence approval: %w", err)
	}
	if observationOutcome != "succeeded" && observationOutcome != "mismatch" {
		return nil, "", ErrInvalidRequest
	}
	type candidate struct {
		evidence Evidence
		kind     TrustAnchorKind
	}
	candidates := make([]candidate, 0, len(req.EvidenceIDs))
	for _, id := range req.EvidenceIDs {
		evidence, err := getEvidenceForApproval(ctx, tx, req.ObservationID, id)
		if err != nil {
			return nil, "", err
		}
		kind, err := approvalKind(evidence.Kind, "")
		if err != nil {
			return nil, "", err
		}
		if kind == AnchorTLSCA || kind == AnchorSSHHostCA {
			return nil, "", ErrUnsupportedEvidence
		}
		if kind == AnchorTLSLeaf && !certificateCurrent(evidence, now) {
			return nil, "", ErrUnsupportedEvidence
		}
		if !anchorCompatibleWithProtocol(Protocol(asset.Kind), kind) {
			return nil, "", ErrUnsupportedEvidence
		}
		candidates = append(candidates, candidate{evidence: evidence, kind: kind})
	}
	anchors := make([]TrustAnchor, 0, len(candidates))
	anchorIDs := make([]string, 0, len(candidates))
	evidenceIDs := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		row, err := q.ApproveTrustAnchor(ctx, sqlc.ApproveTrustAnchorParams{
			AssetID: req.AssetID, EndpointRevision: req.ExpectedRevision, Kind: string(candidate.kind),
			Algorithm: candidate.evidence.Algorithm, Sha256Fingerprint: candidate.evidence.Fingerprint, PublicMaterial: candidate.evidence.PublicMaterial,
			RequiredSshPrincipals: []string{}, RequiredDnsNames: []string{}, RequiredIpAddresses: []string{},
			Source: string(req.Source), ObservationID: nullableUUID(req.ObservationID), ApprovedBy: nullableUUID(req.ActorID),
			ApprovedAt: pgtype.Timestamptz{Time: now, Valid: true}, NotBefore: nullableTime(req.NotBefore), ExpiresAt: nullableTime(req.ExpiresAt),
		})
		if err != nil {
			return nil, "", fmt.Errorf("approve evidence trust anchor: %w", err)
		}
		anchor := trustAnchorFromRow(row)
		anchors = append(anchors, anchor)
		anchorIDs = append(anchorIDs, anchor.ID.String())
		evidenceIDs = append(evidenceIDs, candidate.evidence.ID.String())
	}
	if err := s.enqueue(ctx, q, eventAnchorApproved, req.ActorID, req.AssetID, map[string]any{
		"anchor_ids": anchorIDs, "evidence_ids": evidenceIDs, "observation_id": req.ObservationID.String(),
		"source": req.Source, "resolved_identity_change": observationOutcome == "mismatch",
	}); err != nil {
		return nil, "", err
	}
	status, err := s.statusAt(ctx, tx, StatusRequest{AssetID: req.AssetID}, now)
	if err != nil {
		return nil, "", err
	}
	if err := completeMutation(ctx, q, req.RequestID, batchApprovalMutationResponse{Anchors: anchors, Status: status}); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", fmt.Errorf("commit evidence approval: %w", err)
	}
	return anchors, status, nil
}

// RejectObservation explicitly resolves one current-revision mismatch.
func (s *Service) RejectObservation(ctx context.Context, req RejectObservationRequest) (VerificationStatus, error) {
	idempotencyPayload := req
	idempotencyPayload.RequestID = uuid.Nil
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.ObservationID == uuid.Nil || len(req.Reason) > 500 || !utf8.ValidString(req.Reason) {
		return "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin rejection: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	var replay statusMutationResponse
	replayed, err := claimMutation(ctx, q, req.RequestID, "reject_observation", req.AssetID, req.ActorID, idempotencyPayload, &replay)
	if err != nil {
		return "", err
	}
	if replayed {
		return replay.Status, nil
	}
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
	if err := completeMutation(ctx, q, req.RequestID, statusMutationResponse{Status: status}); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit observation rejection: %w", err)
	}
	return status, nil
}

// RevokeAnchor revokes one anchor without modifying overlapping anchors.
func (s *Service) RevokeAnchor(ctx context.Context, req RevokeAnchorRequest) (VerificationStatus, error) {
	idempotencyPayload := req
	idempotencyPayload.RequestID = uuid.Nil
	if req.AssetID == uuid.Nil || req.ExpectedRevision <= 0 || req.AnchorID == uuid.Nil || len(req.Reason) > 500 || !utf8.ValidString(req.Reason) {
		return "", ErrInvalidRequest
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	var replay statusMutationResponse
	replayed, err := claimMutation(ctx, q, req.RequestID, "revoke_trust_anchor", req.AssetID, req.ActorID, idempotencyPayload, &replay)
	if err != nil {
		return "", err
	}
	if replayed {
		return replay.Status, nil
	}
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
	if err := completeMutation(ctx, q, req.RequestID, statusMutationResponse{Status: status}); err != nil {
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

// ListAnchorsPage returns one database-keyset page of anchor history newest first.
func (s *Service) ListAnchorsPage(ctx context.Context, assetID uuid.UUID, page PageRequest) ([]TrustAnchor, bool, error) {
	if assetID == uuid.Nil || !validPageRequest(page) {
		return nil, false, ErrInvalidRequest
	}
	rows, err := sqlc.New(s.pool).ListTrustAnchorPage(ctx, sqlc.ListTrustAnchorPageParams{
		AssetID: assetID, AfterTime: nullableTime(page.AfterTime), AfterID: page.AfterID, PageLimit: int64(page.Limit + 1),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list trust anchor page: %w", err)
	}
	hasMore := len(rows) > page.Limit
	if hasMore {
		rows = rows[:page.Limit]
	}
	out := make([]TrustAnchor, 0, len(rows))
	for _, row := range rows {
		out = append(out, trustAnchorFromRow(row))
	}
	return out, hasMore, nil
}

// GetProbe returns one job only when it belongs to assetID.
func (s *Service) GetProbe(ctx context.Context, assetID, probeID uuid.UUID) (ProbeJob, error) {
	if assetID == uuid.Nil || probeID == uuid.Nil {
		return ProbeJob{}, ErrInvalidRequest
	}
	row, err := sqlc.New(s.pool).GetTargetProbeJob(ctx, sqlc.GetTargetProbeJobParams{ProbeID: probeID, AssetID: assetID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ProbeJob{}, ErrAssetNotFound
	}
	if err != nil {
		return ProbeJob{}, fmt.Errorf("get probe job: %w", err)
	}
	return probeJobFromRow(row), nil
}

// ListProbes returns the immutable job history newest first.
func (s *Service) ListProbes(ctx context.Context, assetID uuid.UUID) ([]ProbeJob, error) {
	if assetID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	rows, err := sqlc.New(s.pool).ListTargetProbeJobs(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("list probe jobs: %w", err)
	}
	out := make([]ProbeJob, 0, len(rows))
	for _, row := range rows {
		out = append(out, probeJobFromRow(row))
	}
	return out, nil
}

// ListProbesPage returns one database-keyset page of probe history newest first.
func (s *Service) ListProbesPage(ctx context.Context, assetID uuid.UUID, page PageRequest) ([]ProbeJob, bool, error) {
	if assetID == uuid.Nil || !validPageRequest(page) {
		return nil, false, ErrInvalidRequest
	}
	rows, err := sqlc.New(s.pool).ListTargetProbeJobPage(ctx, sqlc.ListTargetProbeJobPageParams{
		AssetID: assetID, AfterTime: nullableTime(page.AfterTime), AfterID: page.AfterID, PageLimit: int64(page.Limit + 1),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list probe job page: %w", err)
	}
	hasMore := len(rows) > page.Limit
	if hasMore {
		rows = rows[:page.Limit]
	}
	out := make([]ProbeJob, 0, len(rows))
	for _, row := range rows {
		out = append(out, probeJobFromRow(row))
	}
	return out, hasMore, nil
}

// ListObservations returns display-safe observations and their public evidence.
func (s *Service) ListObservations(ctx context.Context, assetID uuid.UUID) ([]Observation, error) {
	if assetID == uuid.Nil {
		return nil, ErrInvalidRequest
	}
	q := sqlc.New(s.pool)
	rows, err := q.ListTargetIdentityObservations(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("list identity observations: %w", err)
	}
	evidenceRows, err := q.ListAssetIdentityEvidence(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("list asset identity evidence: %w", err)
	}
	evidenceByObservation := make(map[uuid.UUID][]Evidence)
	for _, row := range evidenceRows {
		evidenceByObservation[row.ObservationID] = append(evidenceByObservation[row.ObservationID], evidenceFromRow(row))
	}
	out := make([]Observation, 0, len(rows))
	for _, row := range rows {
		var addresses []string
		if err := json.Unmarshal(row.ResolvedAddresses, &addresses); err != nil {
			return nil, fmt.Errorf("decode observation addresses: %w", err)
		}
		var metadata protocolMetadata
		if err := json.Unmarshal(row.ProtocolMetadata, &metadata); err != nil {
			return nil, fmt.Errorf("decode observation protocol metadata: %w", err)
		}
		out = append(out, Observation{
			ID: row.ID, JobID: uuidFromPG(row.JobID), AssetID: row.AssetID, EndpointRevision: row.EndpointRevision,
			Source: ObservationSource(row.Source), ResolvedAddresses: addresses, ObservedAt: row.ObservedAt,
			Outcome: row.Outcome, ValidationState: row.ValidationState, FailureCategory: FailureCategory(textFromPG(row.FailureCategory)),
			FailureDetail: textFromPG(row.FailureDetail), Evidence: evidenceByObservation[row.ID],
			SSH: metadata.SSH, TLS: metadata.TLS, Kubernetes: metadata.Kubernetes,
		})
	}
	return out, nil
}

// ListObservationsPage returns one database-keyset page and loads evidence only
// for the observations retained in that page.
func (s *Service) ListObservationsPage(ctx context.Context, assetID uuid.UUID, page PageRequest) ([]Observation, bool, error) {
	if assetID == uuid.Nil || !validPageRequest(page) {
		return nil, false, ErrInvalidRequest
	}
	q := sqlc.New(s.pool)
	rows, err := q.ListTargetIdentityObservationPage(ctx, sqlc.ListTargetIdentityObservationPageParams{
		AssetID: assetID, AfterTime: nullableTime(page.AfterTime), AfterID: page.AfterID, PageLimit: int64(page.Limit + 1),
	})
	if err != nil {
		return nil, false, fmt.Errorf("list identity observation page: %w", err)
	}
	hasMore := len(rows) > page.Limit
	if hasMore {
		rows = rows[:page.Limit]
	}
	observationIDs := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		observationIDs = append(observationIDs, row.ID)
	}
	evidenceByObservation := make(map[uuid.UUID][]Evidence, len(rows))
	if len(observationIDs) > 0 {
		evidenceRows, err := q.ListObservationPageEvidence(ctx, observationIDs)
		if err != nil {
			return nil, false, fmt.Errorf("list observation page evidence: %w", err)
		}
		for _, row := range evidenceRows {
			evidenceByObservation[row.ObservationID] = append(evidenceByObservation[row.ObservationID], evidenceFromRow(row))
		}
	}
	out, err := observationsFromRows(rows, evidenceByObservation)
	if err != nil {
		return nil, false, err
	}
	return out, hasMore, nil
}

func validPageRequest(page PageRequest) bool {
	if page.Limit < 1 || page.Limit > 100 {
		return false
	}
	return page.AfterTime.IsZero() == (page.AfterID == uuid.Nil)
}

func observationsFromRows(rows []sqlc.TargetIdentityObservation, evidenceByObservation map[uuid.UUID][]Evidence) ([]Observation, error) {
	out := make([]Observation, 0, len(rows))
	for _, row := range rows {
		var addresses []string
		if err := json.Unmarshal(row.ResolvedAddresses, &addresses); err != nil {
			return nil, fmt.Errorf("decode observation addresses: %w", err)
		}
		var metadata protocolMetadata
		if err := json.Unmarshal(row.ProtocolMetadata, &metadata); err != nil {
			return nil, fmt.Errorf("decode observation protocol metadata: %w", err)
		}
		out = append(out, Observation{
			ID: row.ID, JobID: uuidFromPG(row.JobID), AssetID: row.AssetID, EndpointRevision: row.EndpointRevision,
			Source: ObservationSource(row.Source), ResolvedAddresses: addresses, ObservedAt: row.ObservedAt,
			Outcome: row.Outcome, ValidationState: row.ValidationState, FailureCategory: FailureCategory(textFromPG(row.FailureCategory)),
			FailureDetail: textFromPG(row.FailureDetail), Evidence: evidenceByObservation[row.ID],
			SSH: metadata.SSH, TLS: metadata.TLS, Kubernetes: metadata.Kubernetes,
		})
	}
	return out, nil
}
