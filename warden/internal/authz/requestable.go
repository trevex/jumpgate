package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Requestable eligibility (the request_policy model). A role R is requestable on
// asset A iff:
//  1. an effective request_policy for (R, A) resolves — most-specific by scope:
//     asset A > nearest ancestor folder > role-default (scope NULL); AND
//  2. the user is ELIGIBLE — either the policy names a requester_role_id the user
//     holds STANDING on A (governance predicate, JIT grants excluded), OR the user
//     (directly or via a nested group) is a kind='requester' subject; AND
//  3. the user does NOT already hold R active on A (grants count — active excludes
//     requestable).
//
// A policy with NO requester_role_id AND no kind='requester' subjects makes nobody
// eligible: a NULL requester_role is NOT "anyone".
//
// Grants confer access but not governance, so this uses two closures: authz_held
// (grant-augmented, for the active-exclusion — the same closure Check uses) and
// authz_held_standing (standing-only, for the requester predicate). Reached via the
// static sqlc queries, so eligibility cannot diverge from Check.

// requestableRoles returns the roles requestable (but not already active) for the
// user on the asset, per the request_policy eligibility model above.
func (s *Authorizer) requestableRoles(ctx context.Context, userID, assetID uuid.UUID) ([]uuid.UUID, error) {
	out, err := s.queries().RequestableRolesOnAsset(ctx, sqlc.RequestableRolesOnAssetParams{User: uuidArg(userID), AssetID: uuidArg(assetID)})
	if err != nil {
		return nil, fmt.Errorf("requestable roles: %w", err)
	}
	return out, nil
}

// requestableAsset is one (asset, role) requestable pair across all assets.
type requestableAsset struct {
	AssetID uuid.UUID
	RoleID  uuid.UUID
}

// visibleRequestable returns every (asset, role) requestable pair for the user
// across all assets, per the request_policy eligibility model above.
func (s *Authorizer) visibleRequestable(ctx context.Context, userID uuid.UUID) ([]requestableAsset, error) {
	rows, err := s.queries().VisibleRequestable(ctx, uuidArg(userID))
	if err != nil {
		return nil, fmt.Errorf("visible requestable: %w", err)
	}
	out := make([]requestableAsset, 0, len(rows))
	for _, r := range rows {
		out = append(out, requestableAsset{AssetID: uuid.UUID(r.AssetID.Bytes), RoleID: uuid.UUID(r.RoleID.Bytes)})
	}
	return out, nil
}
