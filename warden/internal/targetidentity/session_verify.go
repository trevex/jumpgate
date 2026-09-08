package targetidentity

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Session-verification sentinels. The dataplane maps these to Connect codes when
// releasing (or refusing to release) a session credential. They are distinct so a
// refusal cannot be mistaken for a generic error and accidentally issued anyway.
var (
	// ErrNoCurrentAnchors means the asset has no current active trust anchor at
	// its current endpoint revision — there is nothing to verify against, so no
	// credential may be released on the enforced path.
	ErrNoCurrentAnchors = errors.New("asset has no current active trust anchors")
	// ErrIdentityMismatch means the worker's observed target fingerprint does not
	// match the anchor it claims to have matched. This is the MITM signal.
	ErrIdentityMismatch = errors.New("observed target identity does not match anchor")
	// ErrCAAnchorSessionUnsupported means the matched anchor is an ssh_host_ca anchor,
	// whose per-session verification needs local chain validation the SSH/russh worker
	// does not yet perform. tls_ca is supported (the pg-proxy worker validates the
	// chain locally); ssh_host_ca stays refused until its worker does the same.
	ErrCAAnchorSessionUnsupported = errors.New("CA-anchor session verification not supported yet")
)

// SessionAnchor is the public trust-constraint material handed to a worker at
// PrepareSession so it can authenticate the target itself. It carries no secrets
// and no credentials — only the identity constraints an operator approved.
type SessionAnchor struct {
	ID                    uuid.UUID
	Kind                  TrustAnchorKind
	Algorithm             string
	Fingerprint           string
	RequiredSSHPrincipals []string
	RequiredDNSNames      []string
	RequiredIPAddresses   []string
}

// SessionAnchors returns the asset's current endpoint revision and its current
// active trust anchors (public constraint material only), for PrepareSession. An
// empty anchor slice is not an error here — enforcement is applied at issue time
// by VerifySessionTarget, and the preparation phase never releases a credential.
func (s *Service) SessionAnchors(ctx context.Context, assetID uuid.UUID) (int64, []SessionAnchor, error) {
	if assetID == uuid.Nil {
		return 0, nil, ErrInvalidRequest
	}
	now := s.now()
	q := sqlc.New(s.pool)
	asset, err := q.GetAsset(ctx, assetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, ErrAssetNotFound
		}
		return 0, nil, fmt.Errorf("read asset revision: %w", err)
	}
	rows, err := q.ListCurrentActiveTrustAnchors(ctx, sqlc.ListCurrentActiveTrustAnchorsParams{AssetID: assetID, AtTime: now})
	if err != nil {
		return 0, nil, fmt.Errorf("list active anchors: %w", err)
	}
	anchors := make([]SessionAnchor, 0, len(rows))
	for _, row := range rows {
		anchors = append(anchors, sessionAnchorFromRow(row))
	}
	return asset.EndpointRevision, anchors, nil
}

// VerifySessionTargetRequest asks warden to confirm a worker's observed target
// identity matches one current active anchor before a credential is released.
type VerifySessionTargetRequest struct {
	AssetID uuid.UUID
	// ReportedRevision is the endpoint revision the worker prepared against; it
	// must equal the asset's CURRENT revision, else the endpoint moved under the
	// session and the match is stale.
	ReportedRevision int64
	// AnchorID is the anchor the worker claims to have matched.
	AnchorID uuid.UUID
	// ObservedFingerprint is the SHA-256 fingerprint the worker observed on the
	// target's identity material.
	ObservedFingerprint string
}

// VerifySessionTarget confirms the worker's observation matches a current active
// anchor for the asset's current endpoint revision, returning the matched anchor
// id on success. It is a thin composition over the existing current-active-anchor
// query plus exact fingerprint equality — it does NOT mint anything.
//
// Scope: exact-key (ssh_host_key) and leaf (tls_leaf) anchors are proven by exact
// fingerprint equality, which is cryptographically sound with just the observed
// fingerprint. A tls_ca anchor is accepted on the strength of it being CURRENT and
// ACTIVE (this is exactly the ListCurrentActiveTrustAnchors gate below): the pg-proxy
// worker already did the full X.509 chain-to-CA + required-name validation locally
// and warden holds only the observed leaf fingerprint (not the chain), so warden
// re-verifies what it can — that the claimed CA anchor is still current, unrevoked,
// and unexpired at this revision — and trusts the mesh-mTLS-authenticated worker's
// chain attestation for the rest. A revoked/expired/stale-revision CA anchor is
// absent from the current set and so is refused (ErrAnchorNotFound), keeping the
// path fail-closed. ssh_host_ca stays refused (its worker does no such local
// validation yet) with ErrCAAnchorSessionUnsupported.
func (s *Service) VerifySessionTarget(ctx context.Context, req VerifySessionTargetRequest) (uuid.UUID, error) {
	if req.AssetID == uuid.Nil || req.AnchorID == uuid.Nil || req.ObservedFingerprint == "" || req.ReportedRevision <= 0 {
		return uuid.Nil, ErrInvalidRequest
	}
	now := s.now()
	q := sqlc.New(s.pool)
	asset, err := q.GetAsset(ctx, req.AssetID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrAssetNotFound
		}
		return uuid.Nil, fmt.Errorf("read asset revision: %w", err)
	}
	if asset.EndpointRevision != req.ReportedRevision {
		return uuid.Nil, ErrStaleRevision
	}
	// ListCurrentActiveTrustAnchors already excludes revoked, expired, not-yet-valid,
	// and stale-revision anchors, so an anchor absent from this set is (from the
	// worker's perspective) not a current active anchor — treat as not found.
	anchors, err := q.ListCurrentActiveTrustAnchors(ctx, sqlc.ListCurrentActiveTrustAnchorsParams{AssetID: req.AssetID, AtTime: now})
	if err != nil {
		return uuid.Nil, fmt.Errorf("list active anchors: %w", err)
	}
	if len(anchors) == 0 {
		return uuid.Nil, ErrNoCurrentAnchors
	}
	for _, anchor := range anchors {
		if anchor.ID != req.AnchorID {
			continue
		}
		switch TrustAnchorKind(anchor.Kind) {
		case AnchorSSHHostKey, AnchorTLSLeaf:
			if anchor.Sha256Fingerprint == req.ObservedFingerprint {
				return anchor.ID, nil
			}
			return uuid.Nil, ErrIdentityMismatch
		case AnchorTLSCA:
			// Current + active (proven by presence in the set above). The worker
			// validated the chain to this CA + the required name locally; warden has
			// only the leaf fingerprint, so it gates on currency and trusts that
			// mesh-authenticated attestation. Not a pin — the leaf fingerprint is not
			// compared.
			return anchor.ID, nil
		case AnchorSSHHostCA:
			return uuid.Nil, ErrCAAnchorSessionUnsupported
		default:
			return uuid.Nil, ErrIdentityMismatch
		}
	}
	return uuid.Nil, ErrAnchorNotFound
}

func sessionAnchorFromRow(row sqlc.TargetTrustAnchor) SessionAnchor {
	return SessionAnchor{
		ID:                    row.ID,
		Kind:                  TrustAnchorKind(row.Kind),
		Algorithm:             row.Algorithm,
		Fingerprint:           row.Sha256Fingerprint,
		RequiredSSHPrincipals: row.RequiredSshPrincipals,
		RequiredDNSNames:      row.RequiredDnsNames,
		RequiredIPAddresses:   row.RequiredIpAddresses,
	}
}
