package authz

import (
	"context"

	"github.com/google/uuid"
)

// AssetVisible reports whether assetID is VISIBLE / resolvable to userID under the
// unified catalog-visibility rule, using the FULL scope cascade
// CapabilitiesOnScope(AssetScope(assetID)) — global ∪ ancestor folders ∪ asset —
// WITH the `**` super-capability retained. An asset is visible iff EITHER:
//
//   - MANAGEMENT arm: the caps allow "catalog:asset:read" (so `**` and any
//     catalog:asset:read holder see everything they manage — visibility for `**`
//     MUST be preserved; do NOT strip it here), OR
//   - CONNECT arm: the caps entitle at least one of the asset's own SSH logins
//     (folder-scoped ssh:login bindings surface their assets).
//
// An asset the caller matches on NEITHER arm stays invisible (existence-hiding).
//
// This is the single-asset predicate shared by ResolveAsset and GetAssetAccess;
// VisibleAssetsUnder implements the same rule in batch (with a manageable
// short-circuit) rather than calling this per asset in a tight loop.
func AssetVisible(ctx context.Context, a Authorizer, userID, assetID uuid.UUID) (bool, error) {
	caps, err := a.CapabilitiesOnScope(ctx, userID, AssetScope(assetID))
	if err != nil {
		return false, err
	}
	// Management arm: retains `**` (unlike the connect DECISION, which strips it).
	if caps.Allows("catalog:asset:read") {
		return true, nil
	}
	// Connect arm: any entitled login among the asset's declared logins.
	logins, err := assetLoginNames(ctx, a, assetID)
	if err != nil {
		return false, err
	}
	return len(caps.EntitledLogins(logins)) > 0, nil
}

// assetLoginNames returns the SSH login names declared on assetID. It uses the
// sqlAuthorizer's batched login fetch when available; otherwise (a non-SQL
// Authorizer) it returns no logins, so the connect arm is a no-op — such an
// Authorizer must implement visibility another way.
func assetLoginNames(ctx context.Context, a Authorizer, assetID uuid.UUID) ([]string, error) {
	s, ok := a.(*sqlAuthorizer)
	if !ok {
		return nil, nil
	}
	byID, err := s.assetLoginsFor(ctx, []uuid.UUID{assetID})
	if err != nil {
		return nil, err
	}
	return byID[assetID], nil
}
