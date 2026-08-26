package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// sqlAuthorizer resolves access with recursive SQL over the control-plane Postgres.
// The shared authorization closures live in the DB as inlinable SQL functions
// (authz_held / authz_global_held / …); this type reaches them through the static
// sqlc queries on q. pool is retained for the few remaining ad-hoc queries.
type sqlAuthorizer struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// NewSQLAuthorizer returns an Authorizer backed by Postgres.
func NewSQLAuthorizer(pool *pgxpool.Pool) Authorizer {
	return &sqlAuthorizer{pool: pool, q: sqlc.New(pool)}
}

// queries returns the sqlc query set bound to the authorizer's pool. It lazily
// initialises q for authorizers built as a bare struct literal (the internal
// tests) rather than via NewSQLAuthorizer, so both construction paths reach the
// shared authz SQL functions identically.
func (s *sqlAuthorizer) queries() *sqlc.Queries {
	if s.q == nil {
		s.q = sqlc.New(s.pool)
	}
	return s.q
}

// uuidArg wraps a uuid.UUID as a non-null pgtype.UUID for the generated sqlc
// query params that are typed pgtype.UUID (sqlc emits pgtype.UUID for function
// arguments whose nullability it cannot prove). The authz functions never emit or
// require NULL ids, so the wrapper is always Valid.
func uuidArg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// textArg wraps a string as a non-null pgtype.Text for the generated sqlc query
// params that are typed pgtype.Text.
func textArg(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

// heldCTE is the forward-closure dual of RoleResolver.HoldsRole: it computes, for
// a user (@user), every (role, object) the user holds via direct standing bindings,
// active JIT access_grants, and the explicit role_grants rewrite graph
// (same_object + parent). It is group-aware and cycle-safe.
//
// SINGLE SOURCE OF TRUTH: it is COMPOSED from the shared fragments in
// heldclosure.go (heldCTEPrefix = cteUserGroups + heldClosureSQL("held", true)),
// the very same fragments requestable.go composes its `held` / `held_standing`
// closures from. Because Check's grant decision and the Requestable-tier
// eligibility draw the closure body from one source, they cannot silently
// diverge. Each query still appends its own trailing SELECT (below).
var heldCTE = heldCTEPrefix

func (s *sqlAuthorizer) VisibleAssets(ctx context.Context, userID uuid.UUID) ([]AssetVisibility, error) {
	type acc struct {
		active bool
		seen   map[uuid.UUID]struct{}
		roles  []uuid.UUID
	}
	byAsset := map[uuid.UUID]*acc{}
	var order []uuid.UUID
	get := func(assetID uuid.UUID) *acc {
		a := byAsset[assetID]
		if a == nil {
			a = &acc{seen: map[uuid.UUID]struct{}{}}
			byAsset[assetID] = a
			order = append(order, assetID)
		}
		return a
	}
	addRole := func(a *acc, roleID uuid.UUID) {
		if _, ok := a.seen[roleID]; !ok {
			a.seen[roleID] = struct{}{}
			a.roles = append(a.roles, roleID)
		}
	}

	// Active tier: assets held via the explicit role-rewrite graph (standing).
	heldAssets, err := s.queries().HeldAssets(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets (active): %w", err)
	}
	for _, row := range heldAssets {
		a := get(uuid.UUID(row.ObjectID.Bytes))
		a.active = true
		addRole(a, uuid.UUID(row.RoleID.Bytes))
	}

	// Requestable tier: assets with ≥1 role requestable-but-not-active under the
	// request_policy eligibility model.
	req, err := s.visibleRequestable(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets (requestable): %w", err)
	}
	for _, ra := range req {
		addRole(get(ra.AssetID), ra.RoleID)
	}

	out := make([]AssetVisibility, 0, len(order))
	for _, id := range order {
		a := byAsset[id]
		out = append(out, AssetVisibility{AssetID: id, Active: a.active, RoleIDs: a.roles})
	}
	return out, nil
}

func (s *sqlAuthorizer) RolesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (AssetRoles, error) {
	var r AssetRoles

	// Active: roles held on the asset via the explicit role-rewrite graph.
	activeRoleIDs, err := s.queries().HeldRolesOnAsset(ctx, sqlc.HeldRolesOnAssetParams{User: uuidArg(userID), AssetID: uuidArg(assetID)})
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset (active): %w", err)
	}
	activeSeen := map[uuid.UUID]struct{}{}
	for _, rid := range activeRoleIDs {
		roleID := uuid.UUID(rid.Bytes)
		if _, ok := activeSeen[roleID]; !ok {
			activeSeen[roleID] = struct{}{}
			r.Active = append(r.Active, roleID)
		}
	}

	// Requestable: roles requestable-but-not-active under the request_policy
	// eligibility model (active-exclusion is already applied inside the query).
	req, err := s.requestableRoles(ctx, userID, assetID)
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset (requestable): %w", err)
	}
	r.Requestable = append(r.Requestable, req...)
	return r, nil
}

// CapabilitiesOnAsset returns every capability pattern the user holds on the asset
// via the held (standing) closure: the union of the capability sets of the roles
// held on the asset (directly or via the explicit role-rewrite graph). It runs the
// closure ONCE and flattens all rows' patterns, so callers testing several
// capabilities (per-login entitlement, record-exempt) pay a single query. Glob
// matching happens in Go (CapMatch) via Capabilities.Allows, so the '*' / trailing
// '**' semantics stay in one auditable function rather than embedded regex-in-SQL.
func (s *sqlAuthorizer) CapabilitiesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (Capabilities, error) {
	return s.CapabilitiesOnObject(ctx, userID, assetID, "asset")
}

// CapabilitiesOnObject returns every capability pattern the user holds on the
// given object (kind "asset" or "folder") via the held (standing + active-grant)
// closure — the object-dimension generalization of CapabilitiesOnAsset. It runs
// the held closure once and flattens all matching roles' patterns into a single
// Capabilities set (glob matching stays in Go via CapMatch/Allows).
func (s *sqlAuthorizer) CapabilitiesOnObject(ctx context.Context, userID, objectID uuid.UUID, kind string) (Capabilities, error) {
	rows, err := s.queries().HeldCapabilitiesOnObject(ctx, sqlc.HeldCapabilitiesOnObjectParams{
		User:       uuidArg(userID),
		ObjectKind: textArg(kind),
		ObjectID:   uuidArg(objectID),
	})
	if err != nil {
		return nil, fmt.Errorf("capabilities on object: %w", err)
	}
	var caps Capabilities
	for _, r := range rows {
		caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
	}
	return caps, nil
}

// Check reports whether the user holds a role on the asset whose capability set
// grants the concrete `capability`. It is the SINGLE-QUERY EXISTS form of the
// asset-object held closure + a SQL column-match: the closure/object dimension is
// the SAME one CapabilitiesOnAsset/CapabilitiesOnObject(asset) use (the held
// closure over standing bindings, active JIT grants, and the role_grants rewrite
// graph on that exact asset object), and the glob semantics ('*' / trailing '**')
// are pushed into the three-column predicate proven equivalent to Go CapMatch by
// TestSQLCapMatchMatchesGo. NormalizeCap decomposes the requested capability into
// the (@capScope,@capAction,@capQual) request columns exactly as the
// differential-test harness does.
//
// This deliberately does NOT fold in the folder-management cascade or global
// scopeless bindings — that is CapabilitiesOnScope's job (the management plane).
// Check is the data-plane grant decision, keyed strictly to the asset object.
//
// A nonexistent asset matches no held row, so EXISTS is false with no error.
// `capability` is internal (from workers) and assumed concrete — not proto-validated.
func (s *sqlAuthorizer) Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	reqScope, reqAction, reqQual := NormalizeCap(capability)
	ok, err := s.queries().HeldCheckAssetCapability(ctx, sqlc.HeldCheckAssetCapabilityParams{
		User:      uuidArg(userID),
		AssetID:   uuidArg(assetID),
		CapScope:  textArg(reqScope),
		CapAction: textArg(reqAction),
		CapQual:   textArg(reqQual),
	})
	if err != nil {
		return false, fmt.Errorf("check: %w", err)
	}
	return ok, nil
}

// CapabilitiesOnScope returns the capability patterns the user holds at a
// management scope. Global caps (scopeless standing bindings, closed over
// role_grants) ALWAYS apply. For a folder/asset scope, management authority
// CASCADES STRUCTURALLY down the folder tree: a capability held on folder F
// applies to F, every sub-folder of F, and every asset beneath them — with NO
// per-role parent self-grant (unlike the OPT-IN data-plane heldCTE inheritance,
// which requires a role_grants(R,R,parent) self-edge).
//
// SINGLE SET-BASED QUERY. Rather than fanning out into globalHeldCapabilities +
// folderAncestorsAndSelf + capsOnFolders (+ CapabilitiesOnObject + assetFolderID
// for assets) — 3–5 round-trips per call — the folder/asset arms issue ONE query
// off the combined heldPlusGlobalHeldPrefix (user_groups + held + global_held,
// all composed from the shared closure fragments). The trailing SELECT unions
// the role ids from:
//
//   - global_held — the ALWAYS-applies global caps; and
//   - held rows on the in-scope objects: the asset itself (asset scope) and every
//     ancestor-or-self folder, realizing the structural down-tree cascade via the
//     ltree `@>` operator keyed off the scope folder (folder scope) or the asset's
//     containing folder (asset scope).
//
// GLOBAL-VS-HELD SUBTLETY: global caps are sourced from the global_held closure,
// NOT from held rows with object_id IS NULL. A scopeless binding appears in the
// held closure as (role,'folder',NULL), but held's `parent` rewrite arm cannot
// fire for a NULL object, whereas global_held collapses BOTH rewrite arms to plain
// source→target edges — so the two closures differ and only global_held is the
// faithful global source.
//
// EXISTENCE-HIDING: for a nonexistent asset the `@>` ancestor subselect (keyed off
// the asset's folder via a JOIN on assets) is naturally empty and the asset itself
// matches no held row, so the query yields exactly the global caps with no error —
// preserving the legacy pgx.ErrNoRows→global-only behaviour.
func (s *sqlAuthorizer) CapabilitiesOnScope(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error) {
	switch scope.Kind {
	case ScopeGlobal:
		// Global-only: no object dimension, so the lone global_held closure suffices.
		return s.globalHeldCapabilities(ctx, userID)
	case ScopeFolder:
		// global_held ∪ held on folders in the scope subtree (ltree @>).
		rows, err := s.queries().ScopeCapabilitiesFolder(ctx, sqlc.ScopeCapabilitiesFolderParams{User: userID, ScopeID: scope.ID})
		if err != nil {
			return nil, fmt.Errorf("capabilities on scope: %w", err)
		}
		var caps Capabilities
		for _, r := range rows {
			caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
		}
		return caps, nil
	case ScopeAsset:
		// global_held ∪ held on the asset or its ancestor-or-self folders.
		rows, err := s.queries().ScopeCapabilitiesAsset(ctx, sqlc.ScopeCapabilitiesAssetParams{User: uuidArg(userID), ScopeID: uuidArg(scope.ID)})
		if err != nil {
			return nil, fmt.Errorf("capabilities on scope: %w", err)
		}
		var caps Capabilities
		for _, r := range rows {
			caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
		}
		return caps, nil
	default:
		return nil, fmt.Errorf("unknown scope kind %d", scope.Kind)
	}
}

// capsOnFolders returns the union of the capability patterns the user holds on
// ANY of folderIDs via the held (standing + active-grant) closure. Callers pass
// the full folder ancestor chain (FolderAncestorsAndSelf) so a capability held on
// an ancestor folder cascades down to the scoped object. heldCTE binds the user
// to @user; the folder-id array is @folderIDs (heldCTE references only @user, so
// @folderIDs is free).
func (s *sqlAuthorizer) capsOnFolders(ctx context.Context, userID uuid.UUID, folderIDs []uuid.UUID) (Capabilities, error) {
	if len(folderIDs) == 0 {
		return nil, nil
	}
	rows, err := s.queries().HeldCapabilitiesOnFolders(ctx, sqlc.HeldCapabilitiesOnFoldersParams{User: userID, FolderIds: folderIDs})
	if err != nil {
		return nil, fmt.Errorf("caps on folders: %w", err)
	}
	var caps Capabilities
	for _, r := range rows {
		caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
	}
	return caps, nil
}

// folderAncestorsAndSelfRecursive returns every ancestor-or-self folder id of
// id, walking parent links up to the root via a recursive CTE. Copied from the
// generated FolderAncestorsAndSelf query (db/queries/catalog.sql) to run over
// s.pool. Kept as the differential-test reference; hot paths use
// folderAncestorsAndSelf (ltree-backed) instead.
func (s *sqlAuthorizer) folderAncestorsAndSelfRecursive(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE up AS (
    SELECT folders.id, folders.parent_id FROM folders WHERE folders.id = @id
    UNION ALL
    SELECT f.id, f.parent_id FROM folders f JOIN up ON f.id = up.parent_id
)
SELECT up.id FROM up`, pgx.NamedArgs{"id": id})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []uuid.UUID
	for rows.Next() {
		var fid uuid.UUID
		if err := rows.Scan(&fid); err != nil {
			return nil, err
		}
		items = append(items, fid)
	}
	return items, rows.Err()
}

// assetFolderID returns the (NOT NULL) containing folder id of the asset.
func (s *sqlAuthorizer) assetFolderID(ctx context.Context, assetID uuid.UUID) (uuid.UUID, error) {
	var folderID uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT folder_id FROM assets WHERE id = @assetID`, pgx.NamedArgs{"assetID": assetID}).Scan(&folderID)
	return folderID, err
}
