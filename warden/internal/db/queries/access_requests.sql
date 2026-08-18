-- name: CreateAccessRequest :one
INSERT INTO access_requests (requester_user_id, role_id, asset_id, reason, requested_duration, required_approvals, granted_duration, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetAccessRequestForUpdate :one
SELECT * FROM access_requests WHERE id = $1 FOR UPDATE;

-- name: SetAccessRequestStatus :exec
UPDATE access_requests SET status = $1, resolved_at = $2 WHERE id = $3;

-- name: ListAccessRequestsByRequester :many
SELECT * FROM access_requests WHERE requester_user_id = $1 ORDER BY created_at DESC;

-- name: ListPendingRequests :many
SELECT * FROM access_requests WHERE status = 'pending' ORDER BY created_at DESC;

-- name: GetGrantByRequest :one
SELECT * FROM access_grants WHERE request_id = $1;

-- name: CountApprovals :one
SELECT count(*) FROM access_request_approvals WHERE request_id = $1 AND decision = 'approve';

-- name: AddApproval :one
INSERT INTO access_request_approvals (request_id, approver_user_id, decision)
VALUES ($1, $2, $3)
RETURNING *;

-- name: CreateAccessGrant :one
INSERT INTO access_grants (request_id, role_id, scope_asset_id, subject_user_id, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetGrant :one
SELECT * FROM access_grants WHERE id = $1;

-- name: ListGrantsBySubject :many
SELECT * FROM access_grants WHERE subject_user_id = $1 ORDER BY granted_at DESC;

-- name: ListGrantsFiltered :many
-- Admin listing: all grants (active + past), optionally narrowed to a subject
-- and/or to active-only. sqlc.narg(subject_user_id) NULL => any subject;
-- active_only=false => include revoked/expired.
SELECT * FROM access_grants
WHERE (sqlc.narg(subject_user_id)::uuid IS NULL OR subject_user_id = sqlc.narg(subject_user_id)::uuid)
  AND (NOT @active_only::bool OR (revoked_at IS NULL AND expires_at > now()))
ORDER BY granted_at DESC;

-- name: RevokeGrant :one
UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
WHERE id = $1 AND revoked_at IS NULL
RETURNING *;

-- name: RevokeActiveGrantsForUser :many
UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
WHERE subject_user_id = $1 AND revoked_at IS NULL
RETURNING *;

-- name: ExpireGrants :many
UPDATE access_grants SET revoked_at = now(), revoked_reason = 'expired'
WHERE revoked_at IS NULL AND expires_at <= now()
RETURNING *;
