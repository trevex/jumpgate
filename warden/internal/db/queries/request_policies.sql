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

-- name: ListRequestPoliciesForRole :many
SELECT * FROM request_policies WHERE role_id = $1 ORDER BY id;

-- name: AddPolicySubject :one
INSERT INTO request_policy_subjects (policy_id, kind, subject_user_id, subject_group_id)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetPolicySubject :one
SELECT * FROM request_policy_subjects WHERE id = $1;

-- name: RemovePolicySubject :exec
DELETE FROM request_policy_subjects WHERE id = $1;

-- name: ListPolicySubjects :many
SELECT * FROM request_policy_subjects WHERE policy_id = $1 ORDER BY id;

-- name: GetPolicyByNameAndAsset :one
SELECT * FROM request_policies WHERE name = $1 AND scope_asset_id = $2;
