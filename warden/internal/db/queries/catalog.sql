-- name: ListFolders :many
SELECT * FROM folders WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2;

-- name: GetFolder :one
SELECT * FROM folders WHERE id = $1;

-- name: ListAssetsByFolder :many
SELECT * FROM assets WHERE folder_id = $1 ORDER BY id;

-- name: ListRoles :many
SELECT * FROM roles WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2;

-- name: GetRole :one
SELECT * FROM roles WHERE id = $1;

-- name: ListRolesByIDs :many
SELECT * FROM roles WHERE id = ANY($1::uuid[]);

-- name: ListAssetsByIDs :many
SELECT * FROM assets WHERE id = ANY($1::uuid[]);

-- name: ListRoleBindingsByAsset :many
SELECT * FROM role_bindings WHERE scope_asset_id = $1 ORDER BY id;

-- name: ListRoleBindings :many
SELECT * FROM role_bindings
WHERE (sqlc.narg('role_id')::uuid IS NULL OR role_id = sqlc.narg('role_id'))
  AND (sqlc.narg('scope_folder_id')::uuid IS NULL OR scope_folder_id = sqlc.narg('scope_folder_id'))
  AND (sqlc.narg('scope_asset_id')::uuid IS NULL OR scope_asset_id = sqlc.narg('scope_asset_id'))
  AND (sqlc.narg('subject_user_id')::uuid IS NULL OR subject_user_id = sqlc.narg('subject_user_id'))
  AND (sqlc.narg('subject_group_id')::uuid IS NULL OR subject_group_id = sqlc.narg('subject_group_id'))
ORDER BY id;

-- name: DeleteRoleBinding :exec
DELETE FROM role_bindings WHERE id = $1;

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
