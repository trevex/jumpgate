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
