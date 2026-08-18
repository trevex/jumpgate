-- name: CreateApprovalRule :one
INSERT INTO approval_rules (role_id, scope_folder_id, scope_asset_id, required_approvals, approver_role_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: DeleteApprovalRule :exec
DELETE FROM approval_rules WHERE id = $1;

-- name: GetApprovalRule :one
SELECT * FROM approval_rules WHERE id = $1;

-- name: GetRoleDefaultRule :one
SELECT * FROM approval_rules WHERE role_id = $1 AND scope_folder_id IS NULL AND scope_asset_id IS NULL;

-- name: ListApprovalRulesForRole :many
SELECT * FROM approval_rules WHERE role_id = $1 ORDER BY id;

-- name: AddRuleApprover :one
INSERT INTO approval_rule_approvers (rule_id, subject_user_id, subject_group_id)
VALUES ($1, $2, $3)
RETURNING *;

-- name: DeleteRuleApprover :exec
DELETE FROM approval_rule_approvers WHERE id = $1;

-- name: ListRuleApprovers :many
SELECT * FROM approval_rule_approvers WHERE rule_id = $1 ORDER BY id;
