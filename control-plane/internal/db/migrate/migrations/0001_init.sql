-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text NOT NULL UNIQUE,
    display_name text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE group_memberships (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id        uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_user_id  uuid REFERENCES users(id)  ON DELETE CASCADE,
    member_group_id uuid REFERENCES groups(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT one_member CHECK (
        (member_user_id IS NOT NULL) <> (member_group_id IS NOT NULL)
    ),
    CONSTRAINT no_self_member CHECK (member_group_id IS DISTINCT FROM group_id)
);
CREATE UNIQUE INDEX uq_membership_user  ON group_memberships(group_id, member_user_id)  WHERE member_user_id  IS NOT NULL;
CREATE UNIQUE INDEX uq_membership_group ON group_memberships(group_id, member_group_id) WHERE member_group_id IS NOT NULL;

CREATE TABLE folders (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    parent_id  uuid REFERENCES folders(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT no_self_parent CHECK (parent_id IS DISTINCT FROM id)
);
CREATE INDEX idx_folders_parent ON folders(parent_id);

CREATE TABLE assets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    folder_id  uuid NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    name       text NOT NULL,
    labels     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_assets_folder ON assets(folder_id);
CREATE INDEX idx_assets_labels ON assets USING gin (labels);

CREATE TABLE roles (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('folder','asset')),
    capabilities  jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, resource_type)
);

CREATE TABLE role_bindings (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id          uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (kind IN ('standing','requestable')),
    scope_folder_id  uuid REFERENCES folders(id) ON DELETE CASCADE,
    scope_asset_id   uuid REFERENCES assets(id)  ON DELETE CASCADE,
    subject_user_id  uuid REFERENCES users(id)   ON DELETE CASCADE,
    subject_group_id uuid REFERENCES groups(id)  ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT one_scope CHECK (
        (scope_folder_id IS NOT NULL) <> (scope_asset_id IS NOT NULL)
    ),
    CONSTRAINT one_subject CHECK (
        (subject_user_id IS NOT NULL) <> (subject_group_id IS NOT NULL)
    )
);
CREATE INDEX idx_rb_role          ON role_bindings(role_id);
CREATE INDEX idx_rb_scope_folder  ON role_bindings(scope_folder_id)  WHERE scope_folder_id  IS NOT NULL;
CREATE INDEX idx_rb_scope_asset   ON role_bindings(scope_asset_id)   WHERE scope_asset_id   IS NOT NULL;
CREATE INDEX idx_rb_subj_user     ON role_bindings(subject_user_id)  WHERE subject_user_id  IS NOT NULL;
CREATE INDEX idx_rb_subj_group    ON role_bindings(subject_group_id) WHERE subject_group_id IS NOT NULL;

-- +goose Down
DROP TABLE role_bindings;
DROP TABLE roles;
DROP TABLE assets;
DROP TABLE folders;
DROP TABLE group_memberships;
DROP TABLE groups;
DROP TABLE users;
