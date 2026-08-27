-- name: ListFolders :many
SELECT * FROM folders WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2;

-- name: GetFolder :one
SELECT * FROM folders WHERE id = $1;

-- name: ListFoldersByIDsPaged :many
SELECT * FROM folders
WHERE id = ANY(sqlc.arg('ids')::uuid[])
  AND (
    sqlc.narg('after_name')::text IS NULL
    OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
  )
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: ListAssetsByIDsPaged :many
SELECT * FROM assets
WHERE id = ANY(sqlc.arg('ids')::uuid[])
  AND (
    sqlc.narg('after_name')::text IS NULL
    OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
  )
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: ListRolesByIDsPaged :many
SELECT * FROM roles
WHERE id = ANY($1::uuid[])
  AND (
    sqlc.narg('after_name')::text IS NULL
    OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
  )
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: ListRoles :many
SELECT * FROM roles
WHERE (
  -- keyset for ORDER BY name ASC, id ASC: row-comparison is correct for
  -- same-direction sort (both ascending). A NULL after_name means first page.
  sqlc.narg('after_name')::text IS NULL
  OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
)
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: GetRole :one
SELECT * FROM roles WHERE id = $1;

-- name: GetRoleByNameGlobal :one
SELECT * FROM roles WHERE name = $1 AND folder_id IS NULL;

-- name: GetRoleByFolderAndName :one
SELECT * FROM roles WHERE folder_id = $1 AND name = $2;

-- name: ListRolesByIDs :many
SELECT * FROM roles WHERE id = ANY($1::uuid[]);

-- name: ListAssetsByIDs :many
SELECT * FROM assets WHERE id = ANY($1::uuid[]);

-- name: ListRoleBindingsByAsset :many
SELECT * FROM role_bindings WHERE scope_asset_id = $1 ORDER BY id;

-- name: ListRoleBindings :many
-- Bindings matching the (all-optional) filters, fully resolved for display in SQL:
-- subject kind/name/group-home path/member count, role name, and the binding's scope
-- rendered as a dotted path (or 'global'). Single-sources folder-path rendering via
-- folder_path(); no per-row Go resolution.
SELECT
  rb.id, rb.role_id, rb.scope_folder_id, rb.scope_asset_id,
  rb.subject_user_id, rb.subject_group_id, rb.created_at,
  (CASE WHEN rb.subject_group_id IS NOT NULL THEN 'group' ELSE 'user' END)::text AS subject_kind,
  COALESCE(u.display_name, g.name, '')::text AS subject_display_name,
  folder_path(g.folder_id) AS subject_folder_path,
  COALESCE(gm.cnt, 0)::int AS group_member_count,
  r.name AS role_name,
  (CASE
     WHEN rb.scope_asset_id IS NOT NULL THEN
       CASE WHEN folder_path(sa.folder_id) <> '' THEN sa.name || '.' || folder_path(sa.folder_id) ELSE sa.name END
     WHEN rb.scope_folder_id IS NOT NULL THEN folder_path(rb.scope_folder_id)
     ELSE 'global'
   END)::text AS scope_path
FROM role_bindings rb
JOIN roles r ON r.id = rb.role_id
LEFT JOIN users u ON u.id = rb.subject_user_id
LEFT JOIN groups g ON g.id = rb.subject_group_id
LEFT JOIN assets sa ON sa.id = rb.scope_asset_id
LEFT JOIN LATERAL (SELECT count(*)::int AS cnt FROM group_memberships m WHERE m.group_id = rb.subject_group_id) gm ON rb.subject_group_id IS NOT NULL
WHERE (sqlc.narg('role_id')::uuid IS NULL OR rb.role_id = sqlc.narg('role_id'))
  AND (sqlc.narg('scope_folder_id')::uuid IS NULL OR rb.scope_folder_id = sqlc.narg('scope_folder_id'))
  AND (sqlc.narg('scope_asset_id')::uuid IS NULL OR rb.scope_asset_id = sqlc.narg('scope_asset_id'))
  AND (sqlc.narg('subject_user_id')::uuid IS NULL OR rb.subject_user_id = sqlc.narg('subject_user_id'))
  AND (sqlc.narg('subject_group_id')::uuid IS NULL OR rb.subject_group_id = sqlc.narg('subject_group_id'))
  AND (
    -- keyset for ORDER BY created_at DESC, id ASC: strictly older, or same
    -- instant with a later id. A row-comparison `(created_at,id) < (…)` is WRONG
    -- here — it would invert the id tiebreak.
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR rb.created_at < sqlc.narg('after_ts')
    OR (rb.created_at = sqlc.narg('after_ts') AND rb.id > sqlc.narg('after_id')::uuid)
  )
ORDER BY rb.created_at DESC, rb.id
LIMIT sqlc.arg('lim');

-- name: DeleteRoleBinding :exec
DELETE FROM role_bindings WHERE id = $1;

-- name: DeleteRoleBindingsForRole :exec
-- Removes every standing binding of the role. Part of the DeleteRole cascade.
DELETE FROM role_bindings WHERE role_id = $1;

-- name: GetRoleBinding :one
SELECT * FROM role_bindings WHERE id = $1;

-- name: UpsertSSHAssetConfig :one
INSERT INTO ssh_asset_config (asset_id, host_public_key, target_address)
VALUES ($1, $2, $3)
ON CONFLICT (asset_id) DO UPDATE SET
  host_public_key = EXCLUDED.host_public_key,
  target_address = EXCLUDED.target_address
RETURNING *;

-- name: GetSSHAssetConfig :one
SELECT * FROM ssh_asset_config WHERE asset_id = $1;

-- name: ListSSHAssetLogins :many
SELECT * FROM ssh_asset_login WHERE asset_id = $1 ORDER BY login;

-- name: GetSSHAssetLogin :one
SELECT * FROM ssh_asset_login WHERE asset_id = $1 AND login = $2;

-- name: UpsertSSHAssetLogin :one
INSERT INTO ssh_asset_login (asset_id, login, kind, secret_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (asset_id, login) DO UPDATE SET
  kind = EXCLUDED.kind,
  secret_id = EXCLUDED.secret_id
RETURNING *;

-- name: DeleteSSHAssetLoginsForAsset :exec
DELETE FROM ssh_asset_login WHERE asset_id = $1;

-- name: FolderPath :one
-- Dotted leaf->root path of a single folder (the folder's own name first).
WITH RECURSIVE chain AS (
    SELECT folders.id, folders.parent_id, folders.name, 0 AS depth FROM folders WHERE folders.id = $1
    UNION ALL
    SELECT f.id, f.parent_id, f.name, c.depth + 1
    FROM folders f JOIN chain c ON f.id = c.parent_id
)
SELECT COALESCE(string_agg(chain.name, '.' ORDER BY chain.depth ASC), '')::text AS path FROM chain;

-- name: FolderPaths :many
-- Every folder's full leaf->root dotted path in one query (for list responses).
WITH RECURSIVE chain AS (
    SELECT id, parent_id, name::text AS path FROM folders WHERE parent_id IS NULL
    UNION ALL
    SELECT f.id, f.parent_id, (f.name || '.' || c.path)::text
    FROM folders f JOIN chain c ON f.parent_id = c.id
)
SELECT chain.id, chain.path FROM chain;

-- name: FolderByParentName :one
-- One folder by (parent, name). parent_id NULL matches a top-level folder
-- (IS NOT DISTINCT FROM treats NULL = NULL as a match).
SELECT * FROM folders WHERE parent_id IS NOT DISTINCT FROM $1 AND name = $2;

-- name: AssetByFolderName :one
SELECT * FROM assets WHERE folder_id = $1 AND name = $2;

-- name: FolderAncestorsAndSelf :many
-- Every ancestor-or-self folder id of $1 (the target), walking parent links up
-- to the root. Used for folder-scoped role containment checks.
WITH RECURSIVE up AS (
    SELECT folders.id, folders.parent_id FROM folders WHERE folders.id = $1
    UNION ALL
    SELECT f.id, f.parent_id FROM folders f JOIN up ON f.id = up.parent_id
)
SELECT up.id FROM up;

-- name: DeleteAssetSecretsForAsset :exec
DELETE FROM asset_secrets WHERE asset_id = $1;

-- name: DeleteAsset :exec
DELETE FROM assets WHERE id = $1;

-- name: ListRequestPoliciesByAsset :many
SELECT * FROM request_policies WHERE scope_asset_id = $1 ORDER BY id;

-- name: FolderSubtreeIDs :many
-- All folder ids in the subtree rooted at $1 (including $1 itself).
WITH RECURSIVE sub AS (
    SELECT f.id FROM folders f WHERE f.id = $1
    UNION ALL
    SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id
)
SELECT sub.id FROM sub;

-- name: AssetIDsInFolders :many
SELECT id, folder_id FROM assets WHERE folder_id = ANY($1::uuid[]);

-- name: BindingsScopedToFoldersOrAssets :many
SELECT * FROM role_bindings
WHERE scope_folder_id = ANY($1::uuid[]) OR scope_asset_id = ANY($2::uuid[]);

-- name: PoliciesScopedToFoldersOrAssets :many
SELECT * FROM request_policies
WHERE scope_folder_id = ANY($1::uuid[]) OR scope_asset_id = ANY($2::uuid[]);

-- name: DeleteOrphanSecretsForAsset :exec
-- Drop asset_secrets no longer referenced by any of the asset's logins.
DELETE FROM asset_secrets s
WHERE s.asset_id = $1
  AND s.id NOT IN (SELECT l.secret_id FROM ssh_asset_login l WHERE l.asset_id = $1 AND l.secret_id IS NOT NULL);

-- name: SearchFoldersByIDs :many
-- Name-matching folders within a visible-id set. The `name ILIKE` predicate is
-- served by the pg_trgm GIN index (idx_folders_name_trgm), so search filters by
-- name in the database instead of materializing the whole visible catalog.
SELECT * FROM folders
WHERE id = ANY($1::uuid[]) AND name ILIKE $2
ORDER BY name, id
LIMIT $3;

-- name: SearchAssetsByIDs :many
SELECT * FROM assets
WHERE id = ANY($1::uuid[]) AND name ILIKE $2
ORDER BY name, id
LIMIT $3;

-- name: SearchRolesByIDs :many
SELECT * FROM roles
WHERE id = ANY($1::uuid[]) AND name ILIKE $2
ORDER BY name, id
LIMIT $3;

-- name: SearchGroupsByIDs :many
SELECT * FROM groups
WHERE id = ANY($1::uuid[]) AND name ILIKE $2
ORDER BY name, id
LIMIT $3;
