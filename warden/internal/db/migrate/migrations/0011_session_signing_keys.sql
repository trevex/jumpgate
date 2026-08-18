-- +goose Up
CREATE TABLE session_signing_keys (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sealed      bytea NOT NULL,        -- sealed Ed25519 private key (secrets.Sealer)
    public_key  bytea NOT NULL,        -- raw 32-byte Ed25519 public key
    created_at  timestamptz NOT NULL DEFAULT now(),
    active      boolean NOT NULL DEFAULT true
);
CREATE UNIQUE INDEX uq_active_session_key ON session_signing_keys (active) WHERE active;

-- +goose Down
DROP TABLE session_signing_keys;
