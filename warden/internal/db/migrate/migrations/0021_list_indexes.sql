-- +goose Up
-- Name-ordered browse/index lists: (name/email, id) keyset.
CREATE INDEX IF NOT EXISTS idx_folders_parent_name_id ON folders (parent_id, name, id);
CREATE INDEX IF NOT EXISTS idx_folders_name_id        ON folders (name, id);
CREATE INDEX IF NOT EXISTS idx_assets_folder_name_id  ON assets  (folder_id, name, id);
CREATE INDEX IF NOT EXISTS idx_assets_name_id         ON assets  (name, id);
CREATE INDEX IF NOT EXISTS idx_roles_name_id          ON roles   (name, id);
CREATE INDEX IF NOT EXISTS idx_users_email_id         ON users   (email, id);
CREATE INDEX IF NOT EXISTS idx_groups_name_id         ON groups  (name, id);
CREATE INDEX IF NOT EXISTS idx_asset_secrets_name_id  ON asset_secrets (name, id);

-- Time-ordered lists: (created_at DESC, id) keyset.
-- NOTE: session_recordings PK is session_id (not id); tiebreaker uses session_id.
CREATE INDEX IF NOT EXISTS idx_session_recordings_created_id ON session_recordings (created_at DESC, session_id);
CREATE INDEX IF NOT EXISTS idx_role_bindings_created_id      ON role_bindings      (created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_request_policies_created_id   ON request_policies   (created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_role_grants_created_id        ON role_grants        (created_at DESC, id);
-- NOTE: access_grants uses granted_at (no created_at column).
CREATE INDEX IF NOT EXISTS idx_access_grants_granted_id      ON access_grants      (granted_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_access_requests_created_id    ON access_requests    (created_at DESC, id);
-- NOTE: template referenced policy_subjects; actual table name is request_policy_subjects.
CREATE INDEX IF NOT EXISTS idx_request_policy_subjects_created_id ON request_policy_subjects (created_at DESC, id);
-- NOTE: template referenced group_members; actual table name is group_memberships.
CREATE INDEX IF NOT EXISTS idx_group_memberships_created_id  ON group_memberships  (created_at DESC, id);

-- +goose Down
DROP INDEX IF EXISTS idx_folders_parent_name_id;
DROP INDEX IF EXISTS idx_folders_name_id;
DROP INDEX IF EXISTS idx_assets_folder_name_id;
DROP INDEX IF EXISTS idx_assets_name_id;
DROP INDEX IF EXISTS idx_roles_name_id;
DROP INDEX IF EXISTS idx_users_email_id;
DROP INDEX IF EXISTS idx_groups_name_id;
DROP INDEX IF EXISTS idx_asset_secrets_name_id;
DROP INDEX IF EXISTS idx_session_recordings_created_id;
DROP INDEX IF EXISTS idx_role_bindings_created_id;
DROP INDEX IF EXISTS idx_request_policies_created_id;
DROP INDEX IF EXISTS idx_role_grants_created_id;
DROP INDEX IF EXISTS idx_access_grants_granted_id;
DROP INDEX IF EXISTS idx_access_requests_created_id;
DROP INDEX IF EXISTS idx_request_policy_subjects_created_id;
DROP INDEX IF EXISTS idx_group_memberships_created_id;
