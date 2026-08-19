-- name: CreateCAKey :one
INSERT INTO ca_keys (kind, sealed, public_material) VALUES ($1, $2, $3) RETURNING *;

-- name: GetActiveCA :one
SELECT * FROM ca_keys WHERE kind = $1 AND active;

-- name: SetAssetSecret :one
INSERT INTO asset_secrets (asset_id, name, sealed) VALUES ($1, $2, $3)
ON CONFLICT (asset_id, name) DO UPDATE SET sealed = EXCLUDED.sealed
RETURNING *;

-- name: GetAssetSecret :one
-- Scoped to the owning asset: a config referencing another asset's secret (admin
-- misconfiguration) fails closed rather than leaking a secret cross-asset.
SELECT * FROM asset_secrets WHERE id = $1 AND asset_id = $2;

-- name: DeleteAssetSecret :exec
DELETE FROM asset_secrets WHERE id = $1;

-- name: ListAssetSecrets :many
SELECT id, asset_id, name, created_at FROM asset_secrets WHERE asset_id = $1 ORDER BY name;
