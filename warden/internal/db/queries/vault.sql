-- name: CreateCAKey :one
INSERT INTO ca_keys (kind, sealed, public_material) VALUES ($1, $2, $3) RETURNING *;

-- name: GetActiveCA :one
SELECT * FROM ca_keys WHERE kind = $1 AND active;

-- name: SetAssetSecret :one
INSERT INTO asset_secrets (asset_id, name, sealed) VALUES ($1, $2, $3)
ON CONFLICT (asset_id, name) DO UPDATE SET sealed = EXCLUDED.sealed
RETURNING *;

-- name: GetAssetSecret :one
SELECT * FROM asset_secrets WHERE id = $1;

-- name: DeleteAssetSecret :exec
DELETE FROM asset_secrets WHERE id = $1;

-- name: ListAssetSecrets :many
SELECT id, asset_id, name, created_at FROM asset_secrets WHERE asset_id = $1 ORDER BY name;

-- name: UpsertSSHAssetConfig :one
INSERT INTO ssh_asset_config (asset_id, allowed_logins, auth_method, stored_secret_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (asset_id) DO UPDATE SET
  allowed_logins = EXCLUDED.allowed_logins,
  auth_method = EXCLUDED.auth_method,
  stored_secret_id = EXCLUDED.stored_secret_id
RETURNING *;

-- name: GetSSHAssetConfig :one
SELECT * FROM ssh_asset_config WHERE asset_id = $1;
