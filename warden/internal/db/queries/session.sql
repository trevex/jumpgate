-- name: CreateSessionSigningKey :one
INSERT INTO session_signing_keys (sealed, public_key) VALUES ($1, $2) RETURNING *;

-- name: GetActiveSessionSigningKey :one
SELECT * FROM session_signing_keys WHERE active;

-- name: InsertLiveSession :one
INSERT INTO live_sessions (id, user_id, asset_id, worker_id, grant_id, protocol, principals, client_key_fp)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: DeleteLiveSession :execrows
DELETE FROM live_sessions WHERE id = $1;

-- name: GetLiveSession :one
SELECT * FROM live_sessions WHERE id = $1;

-- name: GetLiveSessionParties :one
SELECT user_id, asset_id, worker_id FROM live_sessions WHERE id = $1;

-- name: ListLiveSessionsByWorker :many
SELECT * FROM live_sessions WHERE worker_id = $1;

-- name: ListLiveSessionsByUserAsset :many
SELECT * FROM live_sessions WHERE user_id = $1 AND asset_id = $2;

-- name: ListLiveSessionsByUser :many
SELECT id FROM live_sessions WHERE user_id = $1;

-- name: MarkLiveSessionTerminating :execrows
UPDATE live_sessions SET terminate_requested_at = now() WHERE id = $1 AND terminate_requested_at IS NULL;

-- name: UpsertWorkerPresence :exec
INSERT INTO worker_presence (worker_id, last_seen_at) VALUES ($1, now())
ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now();

-- name: ListDistinctUserAssetsByWorkers :many
SELECT DISTINCT user_id, asset_id FROM live_sessions WHERE worker_id = ANY($1::text[]);

-- name: ListStaleWorkerSessions :many
SELECT ls.id FROM live_sessions ls
JOIN worker_presence wp ON wp.worker_id = ls.worker_id
WHERE wp.last_seen_at < $1;

-- name: ListStuckTerminatingSessions :many
SELECT id FROM live_sessions
WHERE terminate_requested_at IS NOT NULL AND terminate_requested_at < $1;

-- name: DeleteStaleWorkerPresence :exec
DELETE FROM worker_presence wp
WHERE wp.last_seen_at < $1
  AND NOT EXISTS (SELECT 1 FROM live_sessions ls WHERE ls.worker_id = wp.worker_id);

-- name: ListLiveSessionsByAsset :many
SELECT * FROM live_sessions WHERE asset_id = $1;
