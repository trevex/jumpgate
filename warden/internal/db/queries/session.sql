-- name: CreateSessionSigningKey :one
INSERT INTO session_signing_keys (sealed, public_key) VALUES ($1, $2) RETURNING *;

-- name: GetActiveSessionSigningKey :one
SELECT * FROM session_signing_keys WHERE active;

-- name: InsertLiveSession :one
INSERT INTO live_sessions (id, user_id, asset_id, worker_id, grant_id, protocol, principals, client_key_fp)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: DeleteLiveSession :exec
DELETE FROM live_sessions WHERE id = $1;

-- name: GetLiveSession :one
SELECT * FROM live_sessions WHERE id = $1;

-- name: ListLiveSessionsByWorker :many
SELECT * FROM live_sessions WHERE worker_id = $1;

-- name: ListLiveSessionsByUserAsset :many
SELECT * FROM live_sessions WHERE user_id = $1 AND asset_id = $2;

-- name: MarkLiveSessionTerminating :execrows
UPDATE live_sessions SET terminate_requested_at = now() WHERE id = $1 AND terminate_requested_at IS NULL;
