-- +goose Up
CREATE TABLE worker_presence (
    worker_id    text PRIMARY KEY,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION notify_authz_changed() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('authz_changed', '');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_role_bindings_authz     AFTER DELETE            ON role_bindings     FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();
CREATE TRIGGER trg_group_memberships_authz AFTER DELETE            ON group_memberships FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();
CREATE TRIGGER trg_role_grants_authz       AFTER DELETE OR UPDATE  ON role_grants       FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();
CREATE TRIGGER trg_roles_authz             AFTER UPDATE            ON roles             FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();
CREATE TRIGGER trg_users_authz             AFTER UPDATE            ON users             FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();

-- +goose Down
DROP TRIGGER trg_users_authz ON users;
DROP TRIGGER trg_roles_authz ON roles;
DROP TRIGGER trg_role_grants_authz ON role_grants;
DROP TRIGGER trg_group_memberships_authz ON group_memberships;
DROP TRIGGER trg_role_bindings_authz ON role_bindings;
DROP FUNCTION notify_authz_changed();
DROP TABLE worker_presence;
