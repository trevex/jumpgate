package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sqlAuthorizer resolves access with recursive SQL over the control-plane Postgres.
type sqlAuthorizer struct {
	pool *pgxpool.Pool
}

// NewSQLAuthorizer returns an Authorizer backed by Postgres.
func NewSQLAuthorizer(pool *pgxpool.Pool) Authorizer {
	return &sqlAuthorizer{pool: pool}
}

// heldCTE is the forward-closure dual of RoleResolver.HoldsRole: it computes, for
// a user ($1), every (role, object) the user holds via direct standing bindings,
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
	activeRows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT object_id, role_id FROM held WHERE object_kind = 'asset'`, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets (active): %w", err)
	}
	defer activeRows.Close()
	for activeRows.Next() {
		var assetID, roleID uuid.UUID
		if err := activeRows.Scan(&assetID, &roleID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		a := get(assetID)
		a.active = true
		addRole(a, roleID)
	}
	if err := activeRows.Err(); err != nil {
		return nil, err
	}
	// release the pooled conn before the second query; defer remains as the error-path guard (Close is idempotent)
	activeRows.Close()

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
	activeRows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT role_id FROM held WHERE object_kind = 'asset' AND object_id = $2`, userID, assetID)
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset (active): %w", err)
	}
	defer activeRows.Close()
	activeSeen := map[uuid.UUID]struct{}{}
	for activeRows.Next() {
		var roleID uuid.UUID
		if err := activeRows.Scan(&roleID); err != nil {
			return AssetRoles{}, fmt.Errorf("scan: %w", err)
		}
		if _, ok := activeSeen[roleID]; !ok {
			activeSeen[roleID] = struct{}{}
			r.Active = append(r.Active, roleID)
		}
	}
	if err := activeRows.Err(); err != nil {
		return AssetRoles{}, err
	}
	// release the pooled conn before the second query; defer remains as the error-path guard (Close is idempotent)
	activeRows.Close()

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
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM held h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = $3 AND h.object_id = $2`, userID, objectID, kind)
	if err != nil {
		return nil, fmt.Errorf("capabilities on object: %w", err)
	}
	defer rows.Close()
	return scanCapabilities(rows)
}

// scanCapabilities collects every (scope, action, qualifier) row from
// role_capabilities into a Capabilities set, reconstructing the canonical
// pattern string via ReconstructCap. Shared by CapabilitiesOnObject,
// capsOnFolders, and globalHeldCapabilities.
func scanCapabilities(rows pgx.Rows) (Capabilities, error) {
	var caps Capabilities
	for rows.Next() {
		var s, a, q string
		if err := rows.Scan(&s, &a, &q); err != nil {
			return nil, fmt.Errorf("capabilities scan: %w", err)
		}
		caps = append(caps, ReconstructCap(s, a, q))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("capabilities rows: %w", err)
	}
	return caps, nil
}

// Check reports whether the user holds a role on the asset whose capability set
// grants the concrete `capability`. It fetches the roles' capability patterns held
// on the asset (via CapabilitiesOnAsset) and matches each stored pattern against
// the requested capability with CapMatch, so glob semantics ('*' / trailing '**')
// live in one auditable Go function rather than embedded regex-in-SQL. `capability`
// is internal (from workers) and assumed concrete — it is not proto-validated.
func (s *sqlAuthorizer) Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	caps, err := s.CapabilitiesOnAsset(ctx, userID, assetID)
	if err != nil {
		return false, err
	}
	return caps.Allows(capability), nil
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
		return s.scopeCapabilities(ctx, userID, `
    SELECT h.role_id FROM held h
    WHERE h.object_kind = 'folder'
      AND h.object_id IN (
          SELECT f.id FROM folders f
          WHERE f.path_ids @> (SELECT path_ids FROM folders WHERE id = $2)
      )`, scope.ID)
	case ScopeAsset:
		return s.scopeCapabilities(ctx, userID, `
    SELECT h.role_id FROM held h
    WHERE (h.object_kind = 'asset' AND h.object_id = $2)
       OR (h.object_kind = 'folder'
           AND h.object_id IN (
               SELECT f.id FROM folders f
               WHERE f.path_ids @> (
                   SELECT af.path_ids FROM folders af
                   JOIN assets a ON a.folder_id = af.id
                   WHERE a.id = $2
               )
           ))`, scope.ID)
	default:
		return nil, fmt.Errorf("unknown scope kind %d", scope.Kind)
	}
}

// scopeCapabilities runs the single set-based CapabilitiesOnScope query for a
// folder/asset scope: the DISTINCT capability patterns of every role in
// global_held UNION the held roles selected by objectSelect (which references the
// scoped object id as $2). Shared by the ScopeFolder / ScopeAsset arms above so
// the global-caps-always-apply union and the combined closure prefix live in one
// place; only the in-scope-object predicate differs. Existence-hiding is
// upheld here: for a nonexistent object the objectSelect matches nothing, so the
// result is global-only with no error.
func (s *sqlAuthorizer) scopeCapabilities(ctx context.Context, userID uuid.UUID, objectSelect string, objectID uuid.UUID) (Capabilities, error) {
	rows, err := s.pool.Query(ctx, heldPlusGlobalHeldPrefix+`
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM role_capabilities rc
WHERE rc.role_id IN (
    SELECT role_id FROM global_held
  UNION`+objectSelect+`
)`, userID, objectID)
	if err != nil {
		return nil, fmt.Errorf("capabilities on scope: %w", err)
	}
	defer rows.Close()
	return scanCapabilities(rows)
}

// capsOnFolders returns the union of the capability patterns the user holds on
// ANY of folderIDs via the held (standing + active-grant) closure. Callers pass
// the full folder ancestor chain (FolderAncestorsAndSelf) so a capability held on
// an ancestor folder cascades down to the scoped object. heldCTE binds the user
// to $1; the folder-id array is $2 (heldCTE references only $1, so $2 is free).
func (s *sqlAuthorizer) capsOnFolders(ctx context.Context, userID uuid.UUID, folderIDs []uuid.UUID) (Capabilities, error) {
	if len(folderIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT rc.scope, rc.action, rc.qualifier FROM held h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = 'folder' AND h.object_id = ANY($2::uuid[])`, userID, folderIDs)
	if err != nil {
		return nil, fmt.Errorf("caps on folders: %w", err)
	}
	defer rows.Close()
	return scanCapabilities(rows)
}

// folderAncestorsAndSelfRecursive returns every ancestor-or-self folder id of
// id, walking parent links up to the root via a recursive CTE. Copied from the
// generated FolderAncestorsAndSelf query (db/queries/catalog.sql) to run over
// s.pool. Kept as the differential-test reference; hot paths use
// folderAncestorsAndSelf (ltree-backed) instead.
func (s *sqlAuthorizer) folderAncestorsAndSelfRecursive(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE up AS (
    SELECT folders.id, folders.parent_id FROM folders WHERE folders.id = $1
    UNION ALL
    SELECT f.id, f.parent_id FROM folders f JOIN up ON f.id = up.parent_id
)
SELECT up.id FROM up`, id)
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
	err := s.pool.QueryRow(ctx, `SELECT folder_id FROM assets WHERE id = $1`, assetID).Scan(&folderID)
	return folderID, err
}
