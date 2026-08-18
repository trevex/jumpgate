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
//     requester_role_id the user holds STANDING on A (via the explicit role-rewrite
//     graph, i.e. (requester_role, A) ∈ held_standing — grants excluded, this is a
//     governance predicate), OR the user (directly or via a nested group) is a
//     kind='requester' explicit subject of that policy; AND
//  3. the user does NOT already hold R Active on A — i.e. (R, A) ∉ held (grants
//     count here). (Active excludes requestable.)
//
// A policy with NO requester_role_id AND no kind='requester' subjects makes
// nobody eligible: a NULL requester_role is NOT treated as "anyone".
//
// TWO forward-closures live below (M3c — grants confer access but not governance):
//
//   - `held` (→ `held_on_asset`): the grant-augmented closure, base =
//     `role_bindings ∪ active access_grants`. Used for ACTIVE-EXCLUSION — a role
//     held Active via a JIT grant must NOT be double-offered as Requestable. This
//     is the same forward-closure as heldCTE in sql_authorizer.go.
//
//   - `held_standing` (→ `held_standing_on_asset`): the standing-only closure,
//     base = `role_bindings` ONLY (no grant arm). Used for the REQUESTER PREDICATE
//     ("holds requester_role on A") — a JIT-granted requester_role must NOT make
//     downstream roles Requestable. This is the governance/eligibility membership,
//     dual to RoleResolver.HoldsRoleStanding.
//
// SECURITY — KEEP IN SYNC: the `user_groups` body and the THREE recursive rewrite
// arms (same_object + two parent arms) must be IDENTICAL across `held`,
// `held_standing`, heldCTE (sql_authorizer.go), and visibleRequestableCTE below.
// The two closures differ ONLY in their base: `held` adds the active-grant arm,
// `held_standing` does not. The active-grant arm must stay byte-for-byte identical
// wherever it appears. Divergence in the rewrite arms would make Requestable
// eligibility disagree with Check's grant decision (or with HoldsRoleStanding).
const requestableRolesCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
-- grant-augmented closure (base = bindings ∪ active grants) → active-exclusion.
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
-- standing-only closure (base = bindings ONLY, no grant arm) → requester predicate.
-- Governance membership: a JIT-granted role must NOT confer request eligibility.
held_standing(role_id, object_kind, object_id) AS (
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM held_standing h,
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
-- roles the user already holds Active on asset A (grants count → active-exclusion).
held_on_asset(role_id) AS (
    SELECT role_id FROM held WHERE object_kind = 'asset' AND object_id = $2
),
-- roles the user holds STANDING on asset A (grants excluded → requester predicate).
held_standing_on_asset(role_id) AS (
    SELECT role_id FROM held_standing WHERE object_kind = 'asset' AND object_id = $2
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
  -- eligibility: requester_role held STANDING on A (grants excluded — governance),
  -- OR explicit kind='requester' subject.
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_standing_on_asset ha WHERE ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = $1 OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
    )
  )
  -- active excludes requestable (grants count — a granted-Active role is excluded).
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.role_id = e.role_id)`

// visibleRequestableCTE is the all-assets analogue of requestableRolesCTE: for a
// user ($1) it returns every (asset_id, role_id) pair that is requestable (and
// not already active) across ALL assets. The eligibility and active-exclusion
// semantics are identical; the ancestor/candidate/effective computation is
// generalized per-asset (keyed on the asset id) rather than pinned to one asset.
//
// SECURITY — KEEP IN SYNC: like requestableRolesCTE above, this query carries TWO
// forward-closures: `held` (grant-augmented, base = `role_bindings ∪ active
// access_grants`) for ACTIVE-EXCLUSION, and `held_standing` (standing-only, base =
// `role_bindings` ONLY) for the REQUESTER PREDICATE. The `user_groups` body and the
// three recursive rewrite arms must be IDENTICAL across `held`, `held_standing`,
// heldCTE (sql_authorizer.go), and requestableRolesCTE above; the closures differ
// ONLY in their base. The active-grant arm must stay byte-for-byte identical
// wherever it appears.
const visibleRequestableCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
-- grant-augmented closure (base = bindings ∪ active grants) → active-exclusion.
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
-- standing-only closure (base = bindings ONLY, no grant arm) → requester predicate.
held_standing(role_id, object_kind, object_id) AS (
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM held_standing h,
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
held_standing_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM held_standing WHERE object_kind = 'asset'
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
    -- requester_role held STANDING (grants excluded — governance predicate).
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_standing_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = $1 OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
    )
  )
  -- active excludes requestable (grants count — a granted-Active role is excluded).
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
