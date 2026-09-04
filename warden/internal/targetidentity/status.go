package targetidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

type statusObservation struct {
	id         uuid.UUID
	observedAt time.Time
	outcome    string
}

type mismatchResolution uint8

const (
	mismatchUnresolved mismatchResolution = iota
	mismatchApproved
	mismatchRejected
)

// Status derives current verification state from immutable observations and trust.
func (s *Service) Status(ctx context.Context, req StatusRequest) (VerificationStatus, error) {
	if req.AssetID == uuid.Nil || req.Freshness < 0 {
		return "", ErrInvalidRequest
	}
	return s.status(ctx, s.pool, req)
}

func (s *Service) status(ctx context.Context, db sqlc.DBTX, req StatusRequest) (VerificationStatus, error) {
	q := sqlc.New(db)
	asset, err := q.GetAsset(ctx, req.AssetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrAssetNotFound
		}
		return "", fmt.Errorf("read asset revision: %w", err)
	}
	revision := asset.EndpointRevision

	rows, err := q.ListStatusObservations(ctx, sqlc.ListStatusObservationsParams{AssetID: req.AssetID, EndpointRevision: revision})
	if err != nil {
		return "", fmt.Errorf("list observations for status: %w", err)
	}
	observations := make([]statusObservation, 0, len(rows))
	for _, row := range rows {
		observations = append(observations, statusObservation{id: row.ID, observedAt: row.ObservedAt, outcome: row.Outcome})
	}

	// Identity-change observations are sticky. A later matching probe cannot
	// erase the fact; only an approval tied to that exact observation or an
	// explicit operator rejection resolves it.
	approvedMismatches := make(map[uuid.UUID]struct{})
	for _, observation := range observations {
		if observation.outcome != "mismatch" {
			continue
		}
		resolution, err := observationResolutionState(ctx, db, req.AssetID, revision, observation.id)
		if err != nil {
			return "", err
		}
		switch resolution {
		case mismatchUnresolved:
			return StatusIdentityChanged, nil
		case mismatchApproved:
			approvedMismatches[observation.id] = struct{}{}
		}
	}

	var latestSuccess *statusObservation
	for i := range observations {
		_, approvedMismatch := approvedMismatches[observations[i].id]
		if observations[i].outcome == "succeeded" || approvedMismatch {
			latestSuccess = &observations[i]
			break
		}
	}

	anchors, err := q.ListCurrentActiveTrustAnchors(ctx, req.AssetID)
	if err != nil {
		return "", fmt.Errorf("list active anchors for status: %w", err)
	}
	if latestSuccess != nil {
		matched, err := q.ObservationMatchesCurrentAnchors(ctx, sqlc.ObservationMatchesCurrentAnchorsParams{AssetID: req.AssetID, EndpointRevision: revision, ObservationID: latestSuccess.id})
		if err != nil {
			return "", err
		}
		if matched {
			if req.Freshness > 0 && latestSuccess.observedAt.Before(s.now().Add(-req.Freshness)) {
				return StatusVerificationExpired, nil
			}
			return StatusVerified, nil
		}
		if len(anchors) == 0 {
			return StatusAwaitingApproval, nil
		}
		return StatusIdentityChanged, nil
	}

	job, err := q.GetLatestTerminalProbeJob(ctx, sqlc.GetLatestTerminalProbeJobParams{AssetID: req.AssetID, EndpointRevision: revision})
	if err == nil && job.State == "failed" {
		return StatusProbeFailed, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("read latest probe job: %w", err)
	}
	return StatusPendingVerification, nil
}

func observationResolutionState(ctx context.Context, db sqlc.DBTX, assetID uuid.UUID, revision int64, observationID uuid.UUID) (mismatchResolution, error) {
	q := sqlc.New(db)
	approved, err := q.IsObservationApprovedActive(ctx, sqlc.IsObservationApprovedActiveParams{AssetID: assetID, EndpointRevision: revision, ObservationID: nullableUUID(observationID)})
	if err != nil {
		return mismatchUnresolved, fmt.Errorf("check mismatch approval: %w", err)
	}
	if approved {
		return mismatchApproved, nil
	}
	subject := "asset:" + assetID.String()
	rejected, err := q.IsObservationRejected(ctx, sqlc.IsObservationRejectedParams{Subject: nullableText(subject), ObservationID: nullableText(observationID.String())})
	if err != nil {
		return mismatchUnresolved, fmt.Errorf("check mismatch rejection: %w", err)
	}
	if rejected {
		return mismatchRejected, nil
	}
	return mismatchUnresolved, nil
}

func resultMatchesAnchors(result ProbeResult, anchors []sqlc.TargetTrustAnchor, now time.Time) bool {
	validated := make(map[uuid.UUID]map[string]struct{}, len(result.ValidationFacts))
	for _, fact := range result.ValidationFacts {
		if validated[fact.AnchorID] == nil {
			validated[fact.AnchorID] = make(map[string]struct{})
		}
		validated[fact.AnchorID][fact.EvidenceFingerprint] = struct{}{}
	}
	for _, anchor := range anchors {
		for _, evidence := range result.Evidence {
			switch TrustAnchorKind(anchor.Kind) {
			case AnchorSSHHostKey:
				if evidence.Kind == EvidenceSSHHostKey && evidence.Fingerprint == anchor.Sha256Fingerprint {
					return true
				}
			case AnchorTLSLeaf:
				if evidence.Kind == EvidenceTLSLeaf && evidence.Fingerprint == anchor.Sha256Fingerprint && certificateCurrent(evidence, now) && namesMatch(anchor.RequiredDnsNames, evidence.DNSNames) && namesMatch(anchor.RequiredIpAddresses, evidence.IPAddresses) {
					return true
				}
			case AnchorSSHHostCA:
				_, proved := validated[anchor.ID][evidence.Fingerprint]
				if proved && evidence.Kind == EvidenceSSHHostCertificate && certificateCurrent(evidence, now) && namesMatch(anchor.RequiredSshPrincipals, evidence.SSHPrincipals) {
					return true
				}
			case AnchorTLSCA:
				_, proved := validated[anchor.ID][evidence.Fingerprint]
				if proved && evidence.Kind == EvidenceTLSLeaf && certificateCurrent(evidence, now) && namesMatch(anchor.RequiredDnsNames, evidence.DNSNames) && namesMatch(anchor.RequiredIpAddresses, evidence.IPAddresses) {
					return true
				}
			}
		}
	}
	return false
}

func certificateCurrent(evidence Evidence, now time.Time) bool {
	return !evidence.ValidFrom.IsZero() && !evidence.ValidUntil.IsZero() &&
		!now.Before(evidence.ValidFrom) && now.Before(evidence.ValidUntil)
}

func namesMatch(required, presented []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, want := range required {
		for _, got := range presented {
			if want == got {
				return true
			}
		}
	}
	return false
}
