-- name: CreateRoleGrant :one
INSERT INTO role_grants (role_id, source_role_id, via) VALUES ($1, $2, $3) RETURNING *;

-- name: GetRoleGrant :one
SELECT * FROM role_grants WHERE id = $1;

-- name: DeleteRoleGrant :exec
DELETE FROM role_grants WHERE id = $1;

-- name: DeleteRoleGrantsForRole :exec
-- Removes every rewrite edge touching the role, in either direction (the role as
-- the conferred role_id, or as the source that confers another). Part of DeleteRole.
DELETE FROM role_grants WHERE role_id = $1 OR source_role_id = $1;

-- name: ListRoleGrants :many
SELECT * FROM role_grants
WHERE role_id = sqlc.arg('role_id')
  AND (
    -- keyset for ORDER BY created_at DESC, id ASC: explicitly separate the
    -- time predicate so the id tiebreak is NOT inverted.
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY created_at DESC, id
LIMIT sqlc.arg('lim');
