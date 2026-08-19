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
WHERE ($1::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR user_id = $1)
  AND ($2::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR asset_id = $2)
ORDER BY created_at DESC
LIMIT $3;
