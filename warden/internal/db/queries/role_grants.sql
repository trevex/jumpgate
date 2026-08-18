-- name: CreateRoleGrant :one
INSERT INTO role_grants (role_id, source_role_id, via) VALUES ($1, $2, $3) RETURNING *;

-- name: DeleteRoleGrant :exec
DELETE FROM role_grants WHERE id = $1;

-- name: ListRoleGrants :many
SELECT * FROM role_grants WHERE role_id = $1 ORDER BY id;
