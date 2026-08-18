-- +goose Up
ALTER TABLE approval_rules RENAME TO request_policies;
ALTER TABLE request_policies ADD COLUMN requester_role_id uuid REFERENCES roles(id) ON DELETE RESTRICT;

ALTER TABLE approval_rule_approvers RENAME TO request_policy_subjects;
ALTER TABLE request_policy_subjects RENAME COLUMN rule_id TO policy_id;
ALTER TABLE request_policy_subjects ADD COLUMN kind text NOT NULL DEFAULT 'approver'
    CHECK (kind IN ('requester','approver'));
ALTER TABLE request_policy_subjects ALTER COLUMN kind DROP DEFAULT;

ALTER TABLE users ADD COLUMN deactivated_at timestamptz;

-- +goose Down
ALTER TABLE users DROP COLUMN deactivated_at;
ALTER TABLE request_policy_subjects DROP COLUMN kind;
ALTER TABLE request_policy_subjects RENAME COLUMN policy_id TO rule_id;
ALTER TABLE request_policy_subjects RENAME TO approval_rule_approvers;
ALTER TABLE request_policies DROP COLUMN requester_role_id;
ALTER TABLE request_policies RENAME TO approval_rules;
