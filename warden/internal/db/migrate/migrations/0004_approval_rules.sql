-- +goose Up
CREATE TABLE approval_rules (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id            uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_folder_id    uuid REFERENCES folders(id) ON DELETE CASCADE,
    scope_asset_id     uuid REFERENCES assets(id)  ON DELETE CASCADE,
    required_approvals int NOT NULL DEFAULT 1 CHECK (required_approvals >= 1),
    approver_role_id   uuid REFERENCES roles(id) ON DELETE RESTRICT,
    created_at         timestamptz NOT NULL DEFAULT now(),
    -- scope is NULL (role-level default) OR exactly one of folder/asset (override)
    CONSTRAINT scope_shape CHECK (
        (scope_folder_id IS NULL AND scope_asset_id IS NULL)
        OR ((scope_folder_id IS NOT NULL) <> (scope_asset_id IS NOT NULL))
    )
);
CREATE UNIQUE INDEX uq_rule_role_default ON approval_rules(role_id) WHERE scope_folder_id IS NULL AND scope_asset_id IS NULL;
CREATE UNIQUE INDEX uq_rule_role_folder  ON approval_rules(role_id, scope_folder_id) WHERE scope_folder_id IS NOT NULL;
CREATE UNIQUE INDEX uq_rule_role_asset   ON approval_rules(role_id, scope_asset_id)  WHERE scope_asset_id  IS NOT NULL;

CREATE TABLE approval_rule_approvers (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id          uuid NOT NULL REFERENCES approval_rules(id) ON DELETE CASCADE,
    subject_user_id  uuid REFERENCES users(id)  ON DELETE CASCADE,
    subject_group_id uuid REFERENCES groups(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT one_subject CHECK ((subject_user_id IS NOT NULL) <> (subject_group_id IS NOT NULL))
);
CREATE INDEX idx_ara_rule ON approval_rule_approvers(rule_id);

-- +goose Down
DROP TABLE approval_rule_approvers;
DROP TABLE approval_rules;
