package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
func AssetVisible(ctx context.Context, a *Authorizer, userID, assetID uuid.UUID) (bool, error) {
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

// assetLoginNames returns the SSH login names declared on assetID via the
// Authorizer's batched login fetch.
func assetLoginNames(ctx context.Context, a *Authorizer, assetID uuid.UUID) ([]string, error) {
	byID, err := a.assetLoginsFor(ctx, []uuid.UUID{assetID})
	if err != nil {
		return nil, err
	}
	return byID[assetID], nil
}

// assetLoginsFor returns, for each asset in assetIDs, the set of SSH login names
// declared on it (ssh_asset_login.login). Assets with no logins are absent from
// the map. Batched into a single query so the connect-visibility arm never issues
// a per-asset login lookup.
func (s *Authorizer) assetLoginsFor(ctx context.Context, assetIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	if len(assetIDs) == 0 {
		return map[uuid.UUID][]string{}, nil
	}
	rows, err := s.queries().AssetLoginsForAssets(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("asset logins: %w", err)
	}
	out := map[uuid.UUID][]string{}
	for _, r := range rows {
		out[r.AssetID] = append(out[r.AssetID], r.Login)
	}
	return out, nil
}

// accessibleAssetSet returns the set of asset ids the user can access (VisibleAssets:
// active or requestable) — the ACCESS axis, computed once per call.
func (s *Authorizer) accessibleAssetSet(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	vis, err := s.VisibleAssets(ctx, userID)
	if err != nil {
		return nil, err
	}
	set := make(map[uuid.UUID]struct{}, len(vis))
	for _, v := range vis {
		set[v.AssetID] = struct{}{}
	}
	return set, nil
}

// VisibleAssetsUnder returns the asset ids under `parent` the user may see. See the
// Authorizer interface for the visibility predicate.
//
// SET-BASED: the ACCESS set (VisibleAssets = held asset-objects ∪ requestable) is
// two small constant closure queries collapsed into a uuid[] param; the candidate
// selection, management cascade, and connect cascade are ONE query over
// authz_held + authz_global_held. Total is a small constant — no per-folder and no
// per-residual-asset CapabilitiesOnScope loop.
//
// An asset (whose folder is in scope under `parent`) is visible iff ANY of:
//
//   - ACCESS:     a.id ∈ VisibleAssets(user) (a.id = ANY(@accessIDs)); OR
//   - MANAGEMENT: the user holds "catalog:asset:read" on the asset's folder scope —
//     GLOBAL (global_mgmt.ok) covers every asset, else the asset's folder is a
//     descendant-or-self of a folder where the cap is held (mgmt_anchor_folders,
//     the shared mgmtCascadeCTEs fragment with the asset's NOT-NULL folder as the
//     node folder); OR
//   - CONNECT:    the asset declares ≥1 SSH login L (ssh_asset_login) that the user
//     entitles over the FULL asset-scope cascade — a role in authz_global_held, held on
//     the asset object, or held on an ancestor-or-self folder of the asset's folder
//     carries a capability matching ssh:login:L. This reproduces
//     EntitledLogins on the RAW CapabilitiesOnScope(AssetScope) result: `**`
//     normalizes to (*,*,*) and the column-match makes it match ssh:login:L, so
//     `**` IS RETAINED here (no ConnectCapabilities literal-`**` carve-out).
func (s *Authorizer) VisibleAssetsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	// root + no-cascade holds no assets — short-circuit (also makes the level
	// predicate below never need a FALSE arm).
	if parent == uuid.Nil && !cascade {
		return nil, nil
	}

	// ACCESS set: VisibleAssets (held asset-objects ∪ requestable), one small
	// constant closure pair, collapsed into a uuid[] param (@accessIDs).
	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := make([]uuid.UUID, 0, len(accessible))
	for id := range accessible {
		accessIDs = append(accessIDs, id)
	}

	// The management cascade uses the catalog:asset:read request columns; the
	// browse level is selected by the nullable parent (uuid.Nil == root/NULL) and
	// cascade args inside the query. The connect axis is retained verbatim (a `**`
	// cap normalizes to (*,*,*) and matches ssh:login:L via the column-match).
	reqScope, reqAction, reqQual := NormalizeCap("catalog:asset:read")
	ids, err := s.queries().VisibleAssetsUnder(ctx, sqlc.VisibleAssetsUnderParams{
		User:      userID,
		Parent:    nullableUUIDArg(parent),
		Cascade:   cascade,
		CapScope:  reqScope,
		CapAction: reqAction,
		CapQual:   reqQual,
		AccessIds: accessIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("visible assets under: %w", err)
	}
	return ids, nil
}
