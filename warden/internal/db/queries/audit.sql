-- name: NormalizeJSON :one
SELECT $1::jsonb;

-- name: GetLastAuditEntry :one
SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1;

-- name: LockLastAuditEntry :one
SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE;

-- name: InsertAuditEntry :one
INSERT INTO audit_log (event_type, actor_user_id, subject, details, prev_hash, entry_hash)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAuditEntries :many
SELECT * FROM audit_log ORDER BY seq ASC;
