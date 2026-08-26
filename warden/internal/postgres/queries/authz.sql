-- name: HeldAssets :many
-- VisibleAssets active tier.
SELECT DISTINCT object_id, role_id FROM authz_held(sqlc.arg('user')) WHERE object_kind = 'asset';

-- name: HeldRolesOnAsset :many
-- RolesOnAsset active.
SELECT DISTINCT role_id FROM authz_held(sqlc.arg('user'))
WHERE object_kind = 'asset' AND object_id = sqlc.arg('asset_id');

-- name: HeldCapabilitiesOnObject :many
-- CapabilitiesOnObject.
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = sqlc.arg('object_kind') AND h.object_id = sqlc.arg('object_id');

-- name: HeldCheckAssetCapability :one
-- Check.
SELECT EXISTS (
    SELECT 1 FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'asset' AND h.object_id = sqlc.arg('asset_id')
      AND (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
      AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
      AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
);

-- name: HeldCapabilitiesOnFolders :many
-- capsOnFolders.
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = 'folder' AND h.object_id = ANY(sqlc.arg('folder_ids')::uuid[]);

-- name: HeldRolesAndAssets :many
-- heldRolesAndAssets.
SELECT DISTINCT object_kind, object_id, role_id FROM authz_held(sqlc.arg('user'));

-- name: HeldRoleIDs :many
-- heldRoleIDs.
SELECT DISTINCT role_id FROM authz_held(sqlc.arg('user'));

-- name: HeldFolderCapabilities :many
-- mgmtScopeFolders.
SELECT DISTINCT h.object_id, rc.scope, rc.action, rc.qualifier
FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = 'folder';

-- name: GlobalHeldCapabilities :many
-- globalHeldCapabilities.
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM authz_global_held(sqlc.arg('user')) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id;

-- name: ScopeCapabilitiesFolder :many
-- CapabilitiesOnScope folder arm (global_held ∪ held on folders in the scope subtree).
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM role_capabilities rc
WHERE rc.role_id IN (
    SELECT role_id FROM authz_global_held(sqlc.arg('user'))
  UNION
    SELECT h.role_id FROM authz_held(sqlc.arg('user')) h
    WHERE h.object_kind = 'folder'
      AND h.object_id IN (SELECT f.id FROM folders f
                          WHERE f.path_ids @> (SELECT s.path_ids FROM folders s WHERE s.id = sqlc.arg('scope_id')))
);

-- name: ScopeCapabilitiesAsset :many
-- CapabilitiesOnScope asset arm (global_held ∪ held on the asset or its ancestor-or-self folders).
SELECT DISTINCT rc.scope, rc.action, rc.qualifier
FROM role_capabilities rc
WHERE rc.role_id IN (
    SELECT role_id FROM authz_global_held(sqlc.arg('user'))
  UNION
    SELECT h.role_id FROM authz_held(sqlc.arg('user')) h
    WHERE (h.object_kind = 'asset' AND h.object_id = sqlc.arg('scope_id'))
       OR (h.object_kind = 'folder' AND h.object_id IN (
              SELECT anc.id FROM folders anc
              JOIN assets a ON a.id = sqlc.arg('scope_id')
              WHERE anc.path_ids @> (SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id)))
);

-- name: EffectiveRequestPolicy :one
-- approvals.EffectiveRule.
SELECT policy_id, required_approvals, approver_role_id, requester_role_id, max_duration
FROM authz_effective_request_policy(sqlc.arg('role_id'), sqlc.arg('asset_id'));

-- name: HoldsRole :one
-- RoleResolver.HoldsRole (binding ∪ grant satisfaction over authz_role_goals).
SELECT EXISTS (
    SELECT 1 FROM authz_role_goals(sqlc.arg('role_id'), sqlc.arg('object_kind'), sqlc.arg('object_id')) g
    JOIN role_bindings rb ON rb.role_id = g.role_id
      AND ((g.object_kind='asset' AND rb.scope_asset_id=g.object_id)
        OR (g.object_kind='folder' AND rb.scope_folder_id=g.object_id))
      AND (rb.subject_user_id = sqlc.arg('user')
        OR rb.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
    WHERE authz_user_is_active(sqlc.arg('user'))
  UNION ALL
    SELECT 1 FROM authz_role_goals(sqlc.arg('role_id'), sqlc.arg('object_kind'), sqlc.arg('object_id')) g
    JOIN active_access_grants ag ON ag.role_id = g.role_id
      AND g.object_kind='asset' AND ag.scope_asset_id = g.object_id
      AND ag.subject_user_id = sqlc.arg('user')
    WHERE authz_user_is_active(sqlc.arg('user'))
);

-- name: HoldsRoleStanding :one
-- RoleResolver.HoldsRoleStanding (binding satisfaction only).
SELECT EXISTS (
    SELECT 1 FROM authz_role_goals(sqlc.arg('role_id'), sqlc.arg('object_kind'), sqlc.arg('object_id')) g
    JOIN role_bindings rb ON rb.role_id = g.role_id
      AND ((g.object_kind='asset' AND rb.scope_asset_id=g.object_id)
        OR (g.object_kind='folder' AND rb.scope_folder_id=g.object_id))
      AND (rb.subject_user_id = sqlc.arg('user')
        OR rb.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
    WHERE authz_user_is_active(sqlc.arg('user'))
);

-- name: IsMember :one
-- visible_tree IsMember.
SELECT EXISTS (SELECT 1 FROM authz_user_groups(sqlc.arg('user')) WHERE group_id = sqlc.arg('group'))
   AND authz_user_is_active(sqlc.arg('user'));

-- name: MemberGroupIDs :many
-- memberGroupIDs.
SELECT group_id FROM authz_user_groups(sqlc.arg('user')) WHERE authz_user_is_active(sqlc.arg('user'));

-- name: ExplainRolePaths :many
-- ExplainRole.
SELECT path, binding_id, subject_user_id, subject_group_id
FROM authz_role_goal_paths(sqlc.arg('user'), sqlc.arg('role_id'), sqlc.arg('asset_id'));

-- name: RequestableRolesOnAsset :many
-- [2] requestableRoles: roles requestable (but not already active) for the user on
-- the asset under the request_policy eligibility model. The effective policy per
-- candidate role is authz_effective_request_policy(role, asset); the held /
-- held_standing closures come from the shared authz_held / authz_held_standing
-- functions. A role is requestable iff its effective policy makes the user eligible
-- (requester_role held STANDING on the asset OR an explicit kind='requester'
-- subject) AND the user does not already hold it Active on the asset (grants count).
WITH held_on_asset AS (
    SELECT role_id FROM authz_held(sqlc.arg('user'))
    WHERE object_kind = 'asset' AND object_id = sqlc.arg('asset_id')
),
held_standing_on_asset AS (
    SELECT role_id FROM authz_held_standing(sqlc.arg('user'))
    WHERE object_kind = 'asset' AND object_id = sqlc.arg('asset_id')
),
effective AS (
    SELECT r.role_id, ep.policy_id, ep.requester_role_id
    FROM (SELECT DISTINCT role_id FROM request_policies) r
    JOIN LATERAL authz_effective_request_policy(r.role_id, sqlc.arg('asset_id')) ep ON true
)
SELECT e.role_id
FROM effective e
WHERE
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_standing_on_asset ha WHERE ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = sqlc.arg('user')
               OR rps.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
          AND authz_user_is_active(sqlc.arg('user'))
    )
  )
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.role_id = e.role_id);

-- name: VisibleRequestable :many
-- [3] visibleRequestable: every (asset, role) requestable (and not already active)
-- for the user across ALL assets. The candidate (asset, role) universe is the union
-- of asset-scoped, ancestor-folder-scoped, and scopeless request_policies; per pair
-- the winning policy is authz_effective_request_policy(role, asset) via LATERAL. The
-- eligibility and active-exclusion arms mirror RequestableRolesOnAsset, keyed on the
-- (asset, role) pair.
WITH RECURSIVE
ancestors(asset_id, folder_id, depth) AS (
    SELECT id, folder_id, 0 FROM assets
  UNION ALL
    SELECT a.asset_id, f.parent_id, a.depth + 1
    FROM folders f JOIN ancestors a ON f.id = a.folder_id
    WHERE f.parent_id IS NOT NULL
),
held_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM authz_held(sqlc.arg('user')) WHERE object_kind = 'asset'
),
held_standing_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM authz_held_standing(sqlc.arg('user')) WHERE object_kind = 'asset'
),
candidate_pairs(asset_id, role_id) AS (
    SELECT rp.scope_asset_id, rp.role_id
    FROM request_policies rp WHERE rp.scope_asset_id IS NOT NULL
  UNION
    SELECT an.asset_id, rp.role_id
    FROM request_policies rp JOIN ancestors an ON rp.scope_folder_id = an.folder_id
  UNION
    SELECT a.id, rp.role_id
    FROM request_policies rp CROSS JOIN assets a
    WHERE rp.scope_folder_id IS NULL AND rp.scope_asset_id IS NULL
),
effective AS (
    SELECT cp.asset_id, cp.role_id, ep.policy_id, ep.requester_role_id
    FROM candidate_pairs cp
    JOIN LATERAL authz_effective_request_policy(cp.role_id, cp.asset_id) ep ON true
)
SELECT e.asset_id, e.role_id
FROM effective e
WHERE
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_standing_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = sqlc.arg('user')
               OR rps.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
          AND authz_user_is_active(sqlc.arg('user'))
    )
  )
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.role_id);
