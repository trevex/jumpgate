-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower(sqlc.arg(email));

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: CreateAuthToken :one
INSERT INTO auth_tokens (user_id, token_hash, expires_at, client_ip, user_agent, label)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAuthTokensByUser :many
-- Session inventory for a user: only unexpired sessions, and token_hash is
-- deliberately omitted from the projection so it never round-trips to a caller.
SELECT id, user_id, created_at, last_used_at, expires_at, client_ip, user_agent, label
FROM auth_tokens
WHERE user_id = $1 AND expires_at > now()
ORDER BY created_at DESC;

-- name: TouchAuthToken :exec
UPDATE auth_tokens SET last_used_at = now() WHERE token_hash = $1;

-- name: GetAuthTokenByHash :one
SELECT * FROM auth_tokens WHERE token_hash = $1;

-- name: DeleteAuthToken :exec
DELETE FROM auth_tokens WHERE token_hash = $1;

-- name: DeleteAuthTokenByIDForUser :execrows
-- The user_id predicate is the ownership guard: a caller can only revoke a
-- session that is theirs, regardless of which token id they name.
DELETE FROM auth_tokens WHERE id = $1 AND user_id = $2;

-- name: DeleteAuthTokensByUser :execrows
DELETE FROM auth_tokens WHERE user_id = $1;

-- name: DeleteAuthTokensByUserExcept :execrows
-- "Revoke all my other sessions": deletes every token for the user except the
-- one matching the passed token_hash (the caller's current session).
DELETE FROM auth_tokens WHERE user_id = $1 AND token_hash <> $2;

-- name: DeleteExpiredAuthTokens :exec
DELETE FROM auth_tokens WHERE expires_at < now();

-- name: CountUsers :one
SELECT count(*) FROM users;
