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

-- name: ListAccessRequestsByRequesterPaged :many
-- Keyset pagination for (created_at DESC, id ASC). A row-comparison
-- `(created_at,id) < (…)` is WRONG for DESC+ASC — use the explicit predicate.
SELECT * FROM access_requests
WHERE requester_user_id = sqlc.arg('requester_user_id')::uuid
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY created_at DESC, id
LIMIT sqlc.arg('lim');

-- name: ListPendingRequests :many
SELECT * FROM access_requests WHERE status = 'pending' ORDER BY created_at DESC;

-- name: ListPendingRequestsPaged :many
-- Keyset pagination for pending requests (created_at DESC, id ASC).
SELECT * FROM access_requests
WHERE status = 'pending'
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY created_at DESC, id
LIMIT sqlc.arg('lim');

-- name: ListPendingRequestsByAsset :many
SELECT id, requester_user_id, role_id, asset_id
FROM access_requests
WHERE status = 'pending' AND asset_id = $1;

-- name: ListPendingRequestsByRole :many
SELECT id, requester_user_id, role_id, asset_id
FROM access_requests
WHERE status = 'pending' AND role_id = $1;

-- name: IsUserActive :one
SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND deactivated_at IS NULL);

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

-- name: ListGrantsBySubjectPaged :many
-- Keyset pagination on (granted_at DESC, id ASC) for caller-scoped grants.
SELECT * FROM access_grants
WHERE subject_user_id = sqlc.arg('subject_user_id')::uuid
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR granted_at < sqlc.narg('after_ts')
    OR (granted_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY granted_at DESC, id
LIMIT sqlc.arg('lim');

-- name: ListGrantsFiltered :many
-- Admin listing: all grants (active + past), optionally narrowed to a subject
-- and/or to active-only. sqlc.narg(subject_user_id) NULL => any subject;
-- active_only=false => include revoked/expired.
SELECT * FROM access_grants
WHERE (sqlc.narg(subject_user_id)::uuid IS NULL OR subject_user_id = sqlc.narg(subject_user_id)::uuid)
  AND (NOT @active_only::bool OR (revoked_at IS NULL AND expires_at > now()))
ORDER BY granted_at DESC;

-- name: ListGrantsFilteredPaged :many
-- Admin listing with keyset pagination on (granted_at DESC, id ASC). Filters
-- are all optional (null subject => any subject; active_only=false => all).
SELECT * FROM access_grants
WHERE (sqlc.narg('subject_user_id')::uuid IS NULL OR subject_user_id = sqlc.narg('subject_user_id')::uuid)
  AND (NOT sqlc.arg('active_only')::bool OR (revoked_at IS NULL AND expires_at > now()))
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR granted_at < sqlc.narg('after_ts')
    OR (granted_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY granted_at DESC, id
LIMIT sqlc.arg('lim');

-- name: RevokeGrant :one
-- Predicate is revoked_at IS NULL only (NOT the derived "active" filter with
-- expires_at): a grant past expiry but not yet reaped is still revocable so the
-- deactivation cascade can stamp a reason/actor on it. Authz already excludes it
-- (expires_at > now() is false everywhere), so this is harmless.
UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
WHERE id = $1 AND revoked_at IS NULL
RETURNING *;

-- name: RevokeActiveGrantsForUser :many
UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
WHERE subject_user_id = $1 AND revoked_at IS NULL
RETURNING *;

-- name: RevokeActiveGrantsForRole :many
-- Revokes a role's still-live grants (not yet revoked, not yet expired) so the
-- terminator can tear down the sessions they authorized. Used by the DeleteRole
-- cascade before the role row (and, via FK cascade, these grant rows) is deleted.
UPDATE access_grants SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
WHERE role_id = $1 AND revoked_at IS NULL AND expires_at > now()
RETURNING *;

-- name: ExpireGrants :many
UPDATE access_grants SET revoked_at = now(), revoked_reason = 'expired'
WHERE revoked_at IS NULL AND expires_at <= now()
RETURNING *;
