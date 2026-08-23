-- +goose Up
--
-- Narrow the authz_changed NOTIFY payload to the affected subject user when it is
-- unambiguously a single user, so the dataplane sweeper can re-evaluate only that
-- user's live sessions instead of every session on every change.
--
-- INVARIANT: it is ALWAYS SAFE to emit an empty payload (= full sweep). A specific
-- user id is emitted ONLY when that user is the COMPLETE set of affected principals.
-- Transitive changes (group nesting, group-subject bindings, role rewrites, role-grant
-- edges) still emit empty. When in doubt, empty.

-- Per-row narrowing functions. Each fires FOR EACH ROW, so a multi-row statement
-- emits one NOTIFY per affected user (bounded by rows changed) — correct, each
-- narrows to its own user.

-- +goose StatementBegin
CREATE FUNCTION notify_authz_changed_user_update() RETURNS trigger AS $$
BEGIN
    -- A user row change affects exactly that user.
    PERFORM pg_notify('authz_changed', OLD.id::text);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION notify_authz_changed_membership_delete() RETURNS trigger AS $$
BEGIN
    -- A direct user membership affects exactly that user; a nested group membership
    -- (member_group_id) has a transitive blast radius → full sweep.
    IF OLD.member_user_id IS NOT NULL THEN
        PERFORM pg_notify('authz_changed', OLD.member_user_id::text);
    ELSE
        PERFORM pg_notify('authz_changed', '');
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION notify_authz_changed_binding_delete() RETURNS trigger AS $$
BEGIN
    -- A user-subject binding affects exactly that user; a group-subject binding is
    -- transitive (every direct and nested member) → full sweep.
    IF OLD.subject_user_id IS NOT NULL THEN
        PERFORM pg_notify('authz_changed', OLD.subject_user_id::text);
    ELSE
        PERFORM pg_notify('authz_changed', '');
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Rewire the narrowable tables to their per-row functions.
DROP TRIGGER trg_users_authz ON users;
CREATE TRIGGER trg_users_authz AFTER UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION notify_authz_changed_user_update();

DROP TRIGGER trg_group_memberships_authz ON group_memberships;
CREATE TRIGGER trg_group_memberships_authz AFTER DELETE ON group_memberships
    FOR EACH ROW EXECUTE FUNCTION notify_authz_changed_membership_delete();

DROP TRIGGER trg_role_bindings_authz ON role_bindings;
CREATE TRIGGER trg_role_bindings_authz AFTER DELETE ON role_bindings
    FOR EACH ROW EXECUTE FUNCTION notify_authz_changed_binding_delete();

-- role_grants (DELETE/UPDATE) and roles (UPDATE) remain FOR EACH STATEMENT on the
-- original empty-payload notify_authz_changed(): a role rewrite or grant-edge change
-- affects everyone holding the role, transitively → full sweep, unchanged behavior.

-- +goose Down
DROP TRIGGER trg_role_bindings_authz ON role_bindings;
CREATE TRIGGER trg_role_bindings_authz AFTER DELETE ON role_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();

DROP TRIGGER trg_group_memberships_authz ON group_memberships;
CREATE TRIGGER trg_group_memberships_authz AFTER DELETE ON group_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();

DROP TRIGGER trg_users_authz ON users;
CREATE TRIGGER trg_users_authz AFTER UPDATE ON users
    FOR EACH STATEMENT EXECUTE FUNCTION notify_authz_changed();

DROP FUNCTION notify_authz_changed_binding_delete();
DROP FUNCTION notify_authz_changed_membership_delete();
DROP FUNCTION notify_authz_changed_user_update();
