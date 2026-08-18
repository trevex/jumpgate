package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
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
// a user ($1), every (role, object) the user holds via direct standing bindings
// and the explicit role_grants rewrite graph (same_object + parent). It is
// group-aware and cycle-safe (UNION dedup over the finite roles × objects set
// guarantees termination — no depth column needed).
//
// PostgreSQL permits the recursive self-reference exactly once, so the three
// expansion branches are combined via a LATERAL subquery referencing the current
// row h (not the recursive relation).
//
// SECURITY — SINGLE SOURCE OF TRUTH: the `user_groups` + `held` forward-closure
// below is duplicated in requestable.go (requestableRolesCTE,
// visibleRequestableCTE). Check's grant decision and the Requestable-tier
// eligibility MUST resolve membership identically. If you change a role_grants
// expansion arm or the base case here, change ALL copies or eligibility silently
// diverges from Check. (Kept as copies because each query wraps it in different
// trailing CTEs; keep the closure semantics identical.)
//
// The `held` BASE is `role_bindings ∪ active access_grants`: a standing binding
// OR a live JIT grant (M3c). The active-grant arm below (user-subject +
// asset-scope, revoked_at IS NULL AND expires_at > now()) MUST stay byte-for-byte
// identical across all held-style copies. Because activity is filtered by now(),
// an expired/revoked grant stops conferring immediately — no reaper required.
const heldCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
held(role_id, object_kind, object_id) AS (
    -- base: direct standing bindings for the user or a (nested) group
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
  UNION
    -- base: active JIT access_grants (user-subject + asset-scope). SECURITY —
    -- KEEP THIS ARM IDENTICAL across all held-style copies (requestable.go).
    SELECT g.role_id, 'asset'::text, g.scope_asset_id
    FROM access_grants g
    WHERE g.subject_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > now()
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM held h,
    LATERAL (
        -- same_object: hold S on O + rule (R ⊇ S same_object) ⇒ hold R on O
        SELECT rg.role_id, h.object_kind, h.object_id
        FROM role_grants rg
        WHERE rg.source_role_id = h.role_id AND rg.via = 'same_object'
      UNION ALL
        -- parent → child folders of folder O
        SELECT rg.role_id, 'folder'::text, cf.id
        FROM role_grants rg
        JOIN folders cf ON h.object_kind = 'folder' AND cf.parent_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
      UNION ALL
        -- parent → child assets directly in folder O
        SELECT rg.role_id, 'asset'::text, ca.id
        FROM role_grants rg
        JOIN assets ca ON h.object_kind = 'folder' AND ca.folder_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
    ) x
)`

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

// Check reports whether the user holds a role on the asset whose capability set
// grants the concrete `capability`. It fetches the candidate capability sets of
// the roles held on the asset (via the explicit role-rewrite graph) and matches
// each stored pattern against the requested capability with CapMatch, so glob
// semantics ('*' / trailing '**') live in one auditable Go function rather than
// embedded regex-in-SQL. `capability` is internal (from workers) and assumed
// concrete — it is not proto-validated.
func (s *sqlAuthorizer) Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT r.capabilities
FROM held h JOIN roles r ON r.id = h.role_id
WHERE h.object_kind = 'asset' AND h.object_id = $2`, userID, assetID)
	if err != nil {
		return false, fmt.Errorf("check: %w", err)
	}
	defer rows.Close()

	matched := false
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return false, fmt.Errorf("check scan: %w", err)
		}
		if matched {
			continue // keep draining so the pooled conn is fully consumed
		}
		var patterns []string
		if err := json.Unmarshal(raw, &patterns); err != nil {
			return false, fmt.Errorf("check unmarshal capabilities: %w", err)
		}
		for _, p := range patterns {
			if CapMatch(p, capability) {
				matched = true
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("check rows: %w", err)
	}
	return matched, nil
}
