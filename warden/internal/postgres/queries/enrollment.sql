-- name: CreateAgentEnrollmentToken :one
INSERT INTO agent_enrollment_tokens (asset_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ConsumeAgentEnrollmentToken :one
DELETE FROM agent_enrollment_tokens
WHERE token_hash = $1 AND expires_at > now()
RETURNING asset_id;

-- name: DeleteExpiredAgentEnrollmentTokens :exec
DELETE FROM agent_enrollment_tokens WHERE expires_at < now();
