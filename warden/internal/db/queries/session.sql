-- name: CreateSessionSigningKey :one
INSERT INTO session_signing_keys (sealed, public_key) VALUES ($1, $2) RETURNING *;

-- name: GetActiveSessionSigningKey :one
SELECT * FROM session_signing_keys WHERE active;
