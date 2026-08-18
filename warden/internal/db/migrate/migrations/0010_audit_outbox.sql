-- +goose Up
CREATE TABLE audit_outbox (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq           bigint GENERATED ALWAYS AS IDENTITY,
    event_type    text NOT NULL,
    actor_user_id uuid,
    subject       text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_outbox_seq ON audit_outbox(seq);
-- +goose Down
DROP TABLE audit_outbox;
