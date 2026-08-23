-- name: NormalizeJSON :one
SELECT $1::jsonb;

-- name: AcquireAuditLock :exec
SELECT pg_advisory_xact_lock(4919);

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

-- name: AuditChainTip :one
SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1;

-- name: AuditEntryHashAtSeq :one
SELECT entry_hash FROM audit_log WHERE seq = $1;

-- name: EnqueueAuditEvent :one
INSERT INTO audit_outbox (event_type, actor_user_id, subject, details)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: ListUndrainedOutbox :many
SELECT id, event_type, actor_user_id, subject, details
FROM audit_outbox
ORDER BY seq
LIMIT $1;

-- name: DeleteOutboxEvent :exec
DELETE FROM audit_outbox WHERE id = $1;

-- name: CountOutbox :one
SELECT count(*) FROM audit_outbox;
