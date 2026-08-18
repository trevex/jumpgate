-- +goose Up
CREATE TABLE audit_log (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq           bigint GENERATED ALWAYS AS IDENTITY,
    event_type    text NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    subject       text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash     bytea NOT NULL,
    entry_hash    bytea NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (seq),
    UNIQUE (entry_hash)
);
CREATE INDEX idx_audit_seq ON audit_log(seq);

-- +goose Down
DROP TABLE audit_log;
