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

-- name: VisibleAssetsUnder :many
-- [13] VisibleAssetsUnder: asset ids under `parent` the user may see, unifying the
-- ACCESS (access_ids), MANAGEMENT (catalog:asset:read cascade over authz_held /
-- authz_global_held), and CONNECT (ssh:login entitled over the full asset-scope
-- cascade) axes. The (parent, cascade) browse level is selected by the nullable
-- @parent and @cascade args (the (NULL parent, non-cascade) case is short-circuited
-- by the caller and never reaches this query).
WITH mgmt_anchor_folders AS (
    SELECT DISTINCT h.object_id AS folder_id
    FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
      AND (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
      AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
      AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
),
global_mgmt AS (
    SELECT EXISTS (
        SELECT 1 FROM authz_global_held(sqlc.arg('user')) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
        WHERE (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
          AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
          AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
    ) AS ok
),
mgmt_visible_folders AS (
    SELECT DISTINCT nf.id AS folder_id
    FROM mgmt_anchor_folders m
    JOIN folders mf ON mf.id = m.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
)
SELECT a.id
FROM assets a
WHERE (
        (NOT sqlc.arg('cascade')::boolean AND sqlc.narg('parent')::uuid IS NOT NULL AND a.folder_id = sqlc.narg('parent')::uuid)
     OR (sqlc.arg('cascade')::boolean AND (
            sqlc.narg('parent')::uuid IS NULL
            OR a.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = sqlc.narg('parent')::uuid))
        ))
      )
  AND (
        a.id = ANY(sqlc.arg('access_ids')::uuid[])
     OR (SELECT ok FROM global_mgmt)
     OR a.folder_id IN (SELECT folder_id FROM mgmt_visible_folders)
     OR EXISTS (
        SELECT 1 FROM ssh_asset_login sal
        WHERE sal.asset_id = a.id
          AND EXISTS (
              SELECT 1 FROM role_capabilities rc
              WHERE rc.role_id IN (
                    SELECT role_id FROM authz_global_held(sqlc.arg('user'))
                  UNION
                    SELECT h.role_id FROM authz_held(sqlc.arg('user')) h
                    WHERE (h.object_kind = 'asset' AND h.object_id = a.id)
                       OR (h.object_kind = 'folder'
                           AND h.object_id IN (
                               SELECT f.id FROM folders f
                               WHERE f.path_ids @> (SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id)
                           ))
              )
              AND (rc.scope = 'ssh' OR rc.scope = '*')
              AND (rc.action = 'login' OR rc.action = '*')
              AND (rc.qualifier = sal.login OR rc.qualifier = '*')
          )
      )
      )
ORDER BY a.id;

-- name: VisibleRolesHomed :many
-- [18] visibleHomedSetBased(roles): roles homed under `parent` visible to the user,
-- each with its home folder. ACCESS (access_ids) ∪ MANAGEMENT (access:role:read
-- cascade over authz_held / authz_global_held). Level selected by @parent/@cascade.
WITH mgmt_anchor_folders AS (
    SELECT DISTINCT h.object_id AS folder_id
    FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
      AND (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
      AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
      AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
),
global_mgmt AS (
    SELECT EXISTS (
        SELECT 1 FROM authz_global_held(sqlc.arg('user')) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
        WHERE (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
          AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
          AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
    ) AS ok
),
mgmt_visible_folders AS (
    SELECT DISTINCT nf.id AS folder_id
    FROM mgmt_anchor_folders m
    JOIN folders mf ON mf.id = m.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
)
SELECT n.id, n.folder_id
FROM roles n
WHERE (
        (NOT sqlc.arg('cascade')::boolean AND (
            (sqlc.narg('parent')::uuid IS NULL AND n.folder_id IS NULL)
            OR (sqlc.narg('parent')::uuid IS NOT NULL AND n.folder_id = sqlc.narg('parent')::uuid)
        ))
     OR (sqlc.arg('cascade')::boolean AND (
            sqlc.narg('parent')::uuid IS NULL
            OR n.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = sqlc.narg('parent')::uuid))
        ))
      )
  AND (
        n.id = ANY(sqlc.arg('access_ids')::uuid[])
     OR (SELECT ok FROM global_mgmt)
     OR n.folder_id IN (SELECT folder_id FROM mgmt_visible_folders)
      )
ORDER BY n.id;

-- name: VisibleGroupsHomed :many
-- [18] visibleHomedSetBased(groups): groups homed under `parent` visible to the user,
-- each with its home folder. ACCESS (access_ids = transitive membership) ∪ MANAGEMENT
-- (identity:group:read cascade). Table variant of VisibleRolesHomed (FROM groups).
WITH mgmt_anchor_folders AS (
    SELECT DISTINCT h.object_id AS folder_id
    FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
      AND (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
      AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
      AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
),
global_mgmt AS (
    SELECT EXISTS (
        SELECT 1 FROM authz_global_held(sqlc.arg('user')) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
        WHERE (rc.scope = sqlc.arg('cap_scope') OR rc.scope = '*')
          AND (rc.action = sqlc.arg('cap_action') OR rc.action = '*')
          AND (rc.qualifier = sqlc.arg('cap_qual') OR rc.qualifier = '*')
    ) AS ok
),
mgmt_visible_folders AS (
    SELECT DISTINCT nf.id AS folder_id
    FROM mgmt_anchor_folders m
    JOIN folders mf ON mf.id = m.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
)
SELECT n.id, n.folder_id
FROM groups n
WHERE (
        (NOT sqlc.arg('cascade')::boolean AND (
            (sqlc.narg('parent')::uuid IS NULL AND n.folder_id IS NULL)
            OR (sqlc.narg('parent')::uuid IS NOT NULL AND n.folder_id = sqlc.narg('parent')::uuid)
        ))
     OR (sqlc.arg('cascade')::boolean AND (
            sqlc.narg('parent')::uuid IS NULL
            OR n.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = sqlc.narg('parent')::uuid))
        ))
      )
  AND (
        n.id = ANY(sqlc.arg('access_ids')::uuid[])
     OR (SELECT ok FROM global_mgmt)
     OR n.folder_id IN (SELECT folder_id FROM mgmt_visible_folders)
      )
ORDER BY n.id;

-- name: AnchorHomeFolders :many
-- [14] anchorHomeFolders: the union of the three folder-id anchor sources hanging
-- off folder-homed nodes — the home folders of roles/groups visible to the user and
-- the folders of assets visible to the user. Per kind visibility is (the pre-computed
-- ACCESS id set) ∪ (MANAGEMENT via the kind's read cap over authz_held /
-- authz_global_held) ∪ (for assets, CONNECT via an ssh:login entitled over the full
-- asset-scope cascade). Management cascades DOWN a folder subtree (ltree <@).
WITH held_folder_caps(folder_id, scope, action, qualifier) AS (
    SELECT h.object_id, rc.scope, rc.action, rc.qualifier
    FROM authz_held(sqlc.arg('user')) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
),
global_caps(scope, action, qualifier) AS (
    SELECT rc.scope, rc.action, rc.qualifier
    FROM authz_global_held(sqlc.arg('user')) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
),
mgmt_role_folders(folder_id) AS (
    SELECT DISTINCT nf.id
    FROM held_folder_caps hf
    JOIN folders mf ON mf.id = hf.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
    WHERE (hf.scope = 'access' OR hf.scope = '*')
      AND (hf.action = 'role' OR hf.action = '*')
      AND (hf.qualifier = 'read' OR hf.qualifier = '*')
),
mgmt_group_folders(folder_id) AS (
    SELECT DISTINCT nf.id
    FROM held_folder_caps hf
    JOIN folders mf ON mf.id = hf.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
    WHERE (hf.scope = 'identity' OR hf.scope = '*')
      AND (hf.action = 'group' OR hf.action = '*')
      AND (hf.qualifier = 'read' OR hf.qualifier = '*')
),
mgmt_asset_folders(folder_id) AS (
    SELECT DISTINCT nf.id
    FROM held_folder_caps hf
    JOIN folders mf ON mf.id = hf.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
    WHERE (hf.scope = 'catalog' OR hf.scope = '*')
      AND (hf.action = 'asset' OR hf.action = '*')
      AND (hf.qualifier = 'read' OR hf.qualifier = '*')
)
SELECT DISTINCT r.folder_id AS folder_id
FROM roles r
JOIN folders nf ON nf.id = r.folder_id
WHERE r.id = ANY(sqlc.arg('role_access')::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'access' OR c.scope = '*')
                AND (c.action = 'role' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR nf.id IN (SELECT folder_id FROM mgmt_role_folders)
UNION
SELECT DISTINCT g.folder_id AS folder_id
FROM groups g
JOIN folders nf ON nf.id = g.folder_id
WHERE g.id = ANY(sqlc.arg('group_access')::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'identity' OR c.scope = '*')
                AND (c.action = 'group' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR nf.id IN (SELECT folder_id FROM mgmt_group_folders)
UNION
SELECT DISTINCT a.folder_id AS folder_id
FROM assets a
WHERE a.id = ANY(sqlc.arg('asset_access')::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'catalog' OR c.scope = '*')
                AND (c.action = 'asset' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR a.folder_id IN (SELECT folder_id FROM mgmt_asset_folders)
   OR EXISTS (
        SELECT 1 FROM ssh_asset_login sal
        WHERE sal.asset_id = a.id
          AND EXISTS (
              SELECT 1 FROM role_capabilities rc
              WHERE rc.role_id IN (
                    SELECT role_id FROM authz_global_held(sqlc.arg('user'))
                  UNION
                    SELECT h.role_id FROM authz_held(sqlc.arg('user')) h
                    WHERE (h.object_kind = 'asset' AND h.object_id = a.id)
                       OR (h.object_kind = 'folder'
                           AND h.object_id IN (
                               SELECT f.id FROM folders f
                               WHERE f.path_ids @> (SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id)
                           ))
              )
              AND (rc.scope = 'ssh' OR rc.scope = '*')
              AND (rc.action = 'login' OR rc.action = '*')
              AND (rc.qualifier = sal.login OR rc.qualifier = '*')
          )
   );

-- name: ApproverSubjectExists :one
-- [25] approvals.IsApprover explicit-subject arm. The caller is an explicit
-- approver subject of the policy when a request_policy_subjects(kind='approver') row
-- names them directly or via a (nested) group — subject to the deactivation guard.
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects rps
    WHERE rps.policy_id = sqlc.arg('policy_id')
      AND rps.kind = 'approver'
      AND (rps.subject_user_id = sqlc.arg('user')
           OR rps.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
      AND authz_user_is_active(sqlc.arg('user'))
);

-- name: RequesterSubjectExists :one
-- [26] approvals.IsEligibleRequester explicit-subject arm. Mirrors
-- ApproverSubjectExists, differing only by the kind='requester' literal.
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects rps
    WHERE rps.policy_id = sqlc.arg('policy_id')
      AND rps.kind = 'requester'
      AND (rps.subject_user_id = sqlc.arg('user')
           OR rps.subject_group_id IN (SELECT group_id FROM authz_user_groups(sqlc.arg('user'))))
      AND authz_user_is_active(sqlc.arg('user'))
);
