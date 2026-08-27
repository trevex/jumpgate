package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AssetVisible reports whether assetID is visible/resolvable to userID, using the
// FULL scope cascade CapabilitiesOnScope(AssetScope(assetID)) with the `**`
// super-capability retained. Visible iff EITHER:
//   - MANAGEMENT: the caps allow "catalog:asset:read" (retain `**` here — do NOT
//     strip it, unlike the connect DECISION), OR
//   - CONNECT: the caps entitle ≥1 of the asset's own SSH logins.
//
// Matching neither arm stays invisible (existence-hiding). Single-asset predicate
// shared by ResolveAsset and GetAssetAccess; VisibleAssetsUnder is the batch form.
func AssetVisible(ctx context.Context, a *Authorizer, userID, assetID uuid.UUID) (bool, error) {
	caps, err := a.CapabilitiesOnScope(ctx, userID, AssetScope(assetID))
	if err != nil {
		return false, err
	}
	// Management arm: catalog:asset:read OR the subtree-wide catalog:folder:read held
	// on an ancestor folder (ReadAllowed). Retains `**` (unlike the connect DECISION,
	// which strips it).
	if caps.ReadAllowed("catalog:asset:read") {
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

// VisibleAssetsUnder returns the asset ids under `parent` the user may see — the
// batch, set-based form of AssetVisible. The ACCESS set (VisibleAssets) is passed
// as a uuid[] param; candidate selection, management cascade, and connect cascade
// are ONE query over authz_held + authz_global_held (no per-folder loop).
//
// An asset whose folder is in scope under `parent` is visible iff ANY of:
//   - ACCESS:     its id ∈ VisibleAssets(user); OR
//   - MANAGEMENT: the user holds "catalog:asset:read" OR the subtree-wide
//     "catalog:folder:read" (FolderReadCap, READ-only) on the asset's folder scope
//     (global, or the asset's folder descendant-or-self of a folder where the cap
//     is held — the shared mgmtCascadeCTEs fragment); OR
//   - CONNECT:    the asset declares ≥1 SSH login the user entitles over the FULL
//     asset-scope cascade. `**` normalizes to (*,*,*) and matches ssh:login:L, so
//     `**` IS RETAINED here (no ConnectCapabilities literal-`**` carve-out).
func (s *Authorizer) VisibleAssetsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	// root + no-cascade holds no assets — short-circuit (also makes the level
	// predicate below never need a FALSE arm).
	if parent == uuid.Nil && !cascade {
		return nil, nil
	}

	// ACCESS set: VisibleAssets, collapsed into a uuid[] param (@accessIDs).
	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := make([]uuid.UUID, 0, len(accessible))
	for id := range accessible {
		accessIDs = append(accessIDs, id)
	}

	// Browse level is selected by the nullable parent (uuid.Nil == root/NULL) and
	// cascade args inside the query.
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
