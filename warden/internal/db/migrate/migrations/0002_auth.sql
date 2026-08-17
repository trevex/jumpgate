-- +goose Up
ALTER TABLE users ADD COLUMN password_hash text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN is_admin      boolean NOT NULL DEFAULT false;

CREATE TABLE auth_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_tokens_user ON auth_tokens(user_id);

-- +goose Down
DROP TABLE auth_tokens;
ALTER TABLE users DROP COLUMN is_admin;
ALTER TABLE users DROP COLUMN password_hash;
