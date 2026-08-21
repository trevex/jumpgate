-- name: UpsertSessionRecording :exec
INSERT INTO session_recordings (
    session_id, user_id, asset_id, worker_id, protocol, format,
    object_key, size_bytes, sha256, status, started_at, ended_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (session_id) DO UPDATE SET
    size_bytes = EXCLUDED.size_bytes,
    sha256     = EXCLUDED.sha256,
    status     = EXCLUDED.status,
    started_at = EXCLUDED.started_at,
    ended_at   = EXCLUDED.ended_at;

-- name: GetSessionRecording :one
SELECT * FROM session_recordings WHERE session_id = $1;

-- name: ListSessionRecordings :many
SELECT * FROM session_recordings
WHERE (sqlc.narg('user_id')::uuid IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('asset_id')::uuid IS NULL OR asset_id = sqlc.narg('asset_id'))
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND session_id > sqlc.narg('after_session_id')::uuid)
  )
ORDER BY created_at DESC, session_id
LIMIT sqlc.arg('lim');
