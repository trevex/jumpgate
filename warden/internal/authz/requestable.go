package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// requestableRolesCTE computes, for a user ($1) and asset ($2), the set of roles
// that are REQUESTABLE on that asset under the request_policy model.
//
// A role R is requestable on asset A iff:
//  1. an effective request_policy for (R, A) resolves — most-specific by scope:
//     asset A > nearest ancestor folder > role-default (scope NULL); AND
//  2. the user is ELIGIBLE for that policy — either the policy names a
//     requester_role_id the user holds on A (via the explicit role-rewrite graph,
//     i.e. (requester_role, A) ∈ held), OR the user (directly or via a nested
//     group) is a kind='requester' explicit subject of that policy; AND
//  3. the user does NOT already hold R Active (standing) on A — i.e.
//     (R, A) ∉ held. (Active excludes requestable.)
//
// A policy with NO requester_role_id AND no kind='requester' subjects makes
// nobody eligible: a NULL requester_role is NOT treated as "anyone".
//
// The `held` CTE below is the same forward-closure as heldCTE (group-aware,
// role_grants same_object + parent). Evaluating it ONCE serves both the
// "already active" subtraction and the "holds requester_role on A" predicate,
// so the requester predicate composes with groups + parent cascade for free.
//
// SECURITY — KEEP IN SYNC: the `user_groups` + `held` bodies here must resolve
// membership identically to heldCTE in sql_authorizer.go (and to
// visibleRequestableCTE below). Divergence would make Requestable eligibility
// disagree with Check's grant decision. See the note on heldCTE. The `held` base
// is `role_bindings ∪ active access_grants`; the active-grant arm must stay
// byte-for-byte identical across all held-style copies.
const requestableRolesCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
held(role_id, object_kind, object_id) AS (
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
  UNION
    -- base: active JIT access_grants (user-subject + asset-scope). SECURITY —
    -- KEEP THIS ARM IDENTICAL across all held-style copies (sql_authorizer.go).
    SELECT g.role_id, 'asset'::text, g.scope_asset_id
    FROM access_grants g
    WHERE g.subject_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > now()
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM held h,
    LATERAL (
        SELECT rg.role_id, h.object_kind, h.object_id
        FROM role_grants rg
        WHERE rg.source_role_id = h.role_id AND rg.via = 'same_object'
      UNION ALL
        SELECT rg.role_id, 'folder'::text, cf.id
        FROM role_grants rg
        JOIN folders cf ON h.object_kind = 'folder' AND cf.parent_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
      UNION ALL
        SELECT rg.role_id, 'asset'::text, ca.id
        FROM role_grants rg
        JOIN assets ca ON h.object_kind = 'folder' AND ca.folder_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
    ) x
),
-- roles the user already holds Active (standing) on asset A.
held_on_asset(role_id) AS (
    SELECT role_id FROM held WHERE object_kind = 'asset' AND object_id = $2
),
-- ancestor folders of asset A (self-folder at depth 0, walking parent links).
ancestors(folder_id, depth) AS (
    SELECT folder_id, 0 FROM assets WHERE id = $2
  UNION ALL
    SELECT f.parent_id, a.depth + 1 FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
),
-- every request_policy that could apply to (role, asset A), tagged with a
-- specificity: asset override (0) < nearest ancestor folder (depth+1) <
-- role-default scope NULL (1000000).
candidates(role_id, policy_id, requester_role_id, spec) AS (
    SELECT role_id, id, requester_role_id, 0
    FROM request_policies WHERE scope_asset_id = $2
  UNION ALL
    SELECT rp.role_id, rp.id, rp.requester_role_id, a.depth + 1
    FROM request_policies rp JOIN ancestors a ON rp.scope_folder_id = a.folder_id
  UNION ALL
    SELECT role_id, id, requester_role_id, 1000000
    FROM request_policies WHERE scope_folder_id IS NULL AND scope_asset_id IS NULL
),
-- most-specific effective policy per role for asset A.
effective(role_id, policy_id, requester_role_id) AS (
    SELECT DISTINCT ON (role_id) role_id, policy_id, requester_role_id
    FROM candidates
    ORDER BY role_id, spec ASC
)
SELECT e.role_id
FROM effective e
WHERE
  -- eligibility: requester_role held on A, OR explicit kind='requester' subject.
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = $1 OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
    )
  )
  -- active excludes requestable.
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.role_id = e.role_id)`

// visibleRequestableCTE is the all-assets analogue of requestableRolesCTE: for a
// user ($1) it returns every (asset_id, role_id) pair that is requestable (and
// not already active) across ALL assets. The eligibility and active-exclusion
// semantics are identical; the ancestor/candidate/effective computation is
// generalized per-asset (keyed on the asset id) rather than pinned to one asset.
//
// SECURITY — KEEP IN SYNC: the `user_groups` + `held` bodies must resolve
// membership identically to heldCTE (sql_authorizer.go) and requestableRolesCTE
// above. The `held` base is `role_bindings ∪ active access_grants`; the
// active-grant arm must stay byte-for-byte identical across all held-style copies.
const visibleRequestableCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
held(role_id, object_kind, object_id) AS (
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
  UNION
    -- base: active JIT access_grants (user-subject + asset-scope). SECURITY —
    -- KEEP THIS ARM IDENTICAL across all held-style copies (sql_authorizer.go).
    SELECT g.role_id, 'asset'::text, g.scope_asset_id
    FROM access_grants g
    WHERE g.subject_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > now()
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM held h,
    LATERAL (
        SELECT rg.role_id, h.object_kind, h.object_id
        FROM role_grants rg
        WHERE rg.source_role_id = h.role_id AND rg.via = 'same_object'
      UNION ALL
        SELECT rg.role_id, 'folder'::text, cf.id
        FROM role_grants rg
        JOIN folders cf ON h.object_kind = 'folder' AND cf.parent_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
      UNION ALL
        SELECT rg.role_id, 'asset'::text, ca.id
        FROM role_grants rg
        JOIN assets ca ON h.object_kind = 'folder' AND ca.folder_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
    ) x
),
held_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM held WHERE object_kind = 'asset'
),
-- ancestor folders for every asset: (asset_id, folder_id, depth), depth 0 at the
-- asset's own folder, walking parent links upward.
ancestors(asset_id, folder_id, depth) AS (
    SELECT id, folder_id, 0 FROM assets
  UNION ALL
    SELECT a.asset_id, f.parent_id, a.depth + 1
    FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
),
-- candidate policies per (asset, role): asset override (0) < nearest ancestor
-- folder (depth+1) < role-default scope NULL (1000000).
candidates(asset_id, role_id, policy_id, requester_role_id, spec) AS (
    SELECT rp.scope_asset_id, rp.role_id, rp.id, rp.requester_role_id, 0
    FROM request_policies rp WHERE rp.scope_asset_id IS NOT NULL
  UNION ALL
    SELECT an.asset_id, rp.role_id, rp.id, rp.requester_role_id, an.depth + 1
    FROM request_policies rp JOIN ancestors an ON rp.scope_folder_id = an.folder_id
  UNION ALL
    SELECT a.id, rp.role_id, rp.id, rp.requester_role_id, 1000000
    FROM request_policies rp CROSS JOIN assets a
    WHERE rp.scope_folder_id IS NULL AND rp.scope_asset_id IS NULL
),
effective(asset_id, role_id, policy_id, requester_role_id) AS (
    SELECT DISTINCT ON (asset_id, role_id) asset_id, role_id, policy_id, requester_role_id
    FROM candidates
    ORDER BY asset_id, role_id, spec ASC
)
SELECT e.asset_id, e.role_id
FROM effective e
WHERE
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = $1 OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
    )
  )
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.role_id)`

// requestableRoles returns the roles requestable (but not already active) for the
// user on the asset, per the request_policy eligibility model above.
func (s *sqlAuthorizer) requestableRoles(ctx context.Context, userID, assetID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, requestableRolesCTE, userID, assetID)
	if err != nil {
		return nil, fmt.Errorf("requestable roles: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var roleID uuid.UUID
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("requestable roles scan: %w", err)
		}
		out = append(out, roleID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("requestable roles rows: %w", err)
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
func (s *sqlAuthorizer) visibleRequestable(ctx context.Context, userID uuid.UUID) ([]requestableAsset, error) {
	rows, err := s.pool.Query(ctx, visibleRequestableCTE, userID)
	if err != nil {
		return nil, fmt.Errorf("visible requestable: %w", err)
	}
	defer rows.Close()
	var out []requestableAsset
	for rows.Next() {
		var ra requestableAsset
		if err := rows.Scan(&ra.AssetID, &ra.RoleID); err != nil {
			return nil, fmt.Errorf("visible requestable scan: %w", err)
		}
		out = append(out, ra)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("visible requestable rows: %w", err)
	}
	return out, nil
}
