-- +goose Up
CREATE TABLE role_grants (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    source_role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    via            text NOT NULL CHECK (via IN ('same_object','parent')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_id, source_role_id, via),
    CONSTRAINT no_self_same_object CHECK (NOT (role_id = source_role_id AND via = 'same_object'))
);
CREATE INDEX idx_role_grants_role ON role_grants(role_id);
-- +goose Down
DROP TABLE role_grants;
