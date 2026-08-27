-- name: CreateRequestPolicy :one
INSERT INTO request_policies (role_id, scope_folder_id, scope_asset_id, required_approvals, approver_role_id, requester_role_id, max_duration, name)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: UpdateRequestPolicy :one
UPDATE request_policies
SET required_approvals = $2, approver_role_id = $3, requester_role_id = $4, max_duration = $5
WHERE id = $1
RETURNING *;

-- name: DeleteRequestPolicy :exec
DELETE FROM request_policies WHERE id = $1;

-- name: GetRequestPolicy :one
SELECT * FROM request_policies WHERE id = $1;

-- name: GetRoleDefaultPolicy :one
SELECT * FROM request_policies WHERE role_id = $1 AND scope_folder_id IS NULL AND scope_asset_id IS NULL;

-- name: ListRequestPolicies :many
SELECT * FROM request_policies
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

-- name: ListPoliciesForAsset :many
SELECT * FROM request_policies
WHERE scope_asset_id = sqlc.arg('asset_id')
  AND (
    -- keyset for ORDER BY created_at DESC, id ASC: explicitly separate the
    -- time predicate so the id tiebreak is NOT inverted.
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY created_at DESC, id
LIMIT sqlc.arg('lim');

-- name: ListPoliciesForSubjectGroup :many
SELECT * FROM request_policies rp
WHERE rp.id IN (SELECT policy_id FROM request_policy_subjects WHERE subject_group_id = sqlc.arg('group_id'))
  AND (
    -- keyset for ORDER BY created_at DESC, id ASC: explicitly separate the
    -- time predicate so the id tiebreak is NOT inverted.
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR rp.created_at < sqlc.narg('after_ts')
    OR (rp.created_at = sqlc.narg('after_ts') AND rp.id > sqlc.narg('after_id')::uuid)
  )
ORDER BY rp.created_at DESC, rp.id
LIMIT sqlc.arg('lim');

-- name: AddPolicySubject :one
INSERT INTO request_policy_subjects (policy_id, kind, subject_user_id, subject_group_id)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetPolicySubject :one
SELECT * FROM request_policy_subjects WHERE id = $1;

-- name: RemovePolicySubject :exec
DELETE FROM request_policy_subjects WHERE id = $1;

-- name: ListPolicySubjects :many
SELECT * FROM request_policy_subjects
WHERE policy_id = sqlc.arg('policy_id')
  AND (
    -- keyset for ORDER BY created_at DESC, id ASC: explicitly separate the
    -- time predicate so the id tiebreak is NOT inverted.
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR created_at < sqlc.narg('after_ts')
    OR (created_at = sqlc.narg('after_ts') AND id > sqlc.narg('after_id')::uuid)
  )
ORDER BY created_at DESC, id
LIMIT sqlc.arg('lim');

-- name: GetPolicyByNameAndAsset :one
SELECT * FROM request_policies WHERE name = $1 AND scope_asset_id = $2;

-- name: DeletePolicySubjectsForRole :exec
-- Removes the subjects of every policy whose requestable role is $1 (those policies
-- are about to be deleted). Part of the DeleteRole cascade.
DELETE FROM request_policy_subjects
WHERE policy_id IN (SELECT id FROM request_policies WHERE role_id = $1);

-- name: DeletePoliciesForRole :exec
-- Deletes the policies for which the role is the requestable role (meaningless once
-- the role is gone). Part of the DeleteRole cascade.
DELETE FROM request_policies WHERE role_id = $1;

-- name: NullRequesterRoleForRole :exec
-- Clears the requester gate on surviving policies that named the role as their
-- requester role (the policy survives, just loses that gate). Part of DeleteRole.
UPDATE request_policies SET requester_role_id = NULL WHERE requester_role_id = $1;

-- name: NullApproverRoleForRole :exec
-- Clears the approver gate on surviving policies that named the role as their
-- approver role (the policy survives, just loses that gate). Part of DeleteRole.
UPDATE request_policies SET approver_role_id = NULL WHERE approver_role_id = $1;

-- name: ListPoliciesUsingRole :many
-- Every policy that references the role in any position, tagged with how: as the
-- requestable role, as the requester-source role, or as the approver-source role.
-- Bounded (a role appears in few policies); not paginated.
SELECT rp.*, 'requestable'::text AS usage FROM request_policies rp WHERE rp.role_id = sqlc.arg('role_id')
UNION ALL
SELECT rp.*, 'requester_source'::text AS usage FROM request_policies rp WHERE rp.requester_role_id = sqlc.arg('role_id')
UNION ALL
SELECT rp.*, 'approver_source'::text AS usage FROM request_policies rp WHERE rp.approver_role_id = sqlc.arg('role_id')
ORDER BY usage, created_at DESC, id
LIMIT 500;
