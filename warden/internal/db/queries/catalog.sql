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
