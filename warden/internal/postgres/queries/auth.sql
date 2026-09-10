-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower($1);

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: CreateAuthToken :one
INSERT INTO auth_tokens (user_id, token_hash, expires_at, client_ip, user_agent, label)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAuthTokensByUser :many
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
DELETE FROM auth_tokens WHERE id = $1 AND user_id = $2;

-- name: DeleteAuthTokensByUser :execrows
DELETE FROM auth_tokens WHERE user_id = $1;

-- name: DeleteAuthTokensByUserExcept :execrows
DELETE FROM auth_tokens WHERE user_id = $1 AND token_hash <> $2;

-- name: DeleteExpiredAuthTokens :exec
DELETE FROM auth_tokens WHERE expires_at < now();

-- name: CountUsers :one
SELECT count(*) FROM users;
