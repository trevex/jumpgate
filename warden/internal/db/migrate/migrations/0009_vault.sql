-- +goose Up
ALTER TABLE assets ADD COLUMN kind text NOT NULL DEFAULT 'ssh' CHECK (kind IN ('ssh','postgres','k8s'));

CREATE TABLE ca_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            text NOT NULL CHECK (kind IN ('ssh','x509')),
    sealed          bytea NOT NULL,
    public_material text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    active          boolean NOT NULL DEFAULT true
);
CREATE UNIQUE INDEX uq_active_ca ON ca_keys (kind) WHERE active;

CREATE TABLE asset_secrets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id   uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name       text NOT NULL,
    sealed     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, name)
);

CREATE TABLE ssh_asset_config (
    asset_id         uuid PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    allowed_logins   text[] NOT NULL,
    auth_method      text NOT NULL CHECK (auth_method IN ('ca-cert','stored-key')),
    stored_secret_id uuid REFERENCES asset_secrets(id) ON DELETE RESTRICT,
    CONSTRAINT stored_key_needs_secret CHECK (auth_method <> 'stored-key' OR stored_secret_id IS NOT NULL)
);

-- +goose Down
DROP TABLE ssh_asset_config;
DROP TABLE asset_secrets;
DROP TABLE ca_keys;
ALTER TABLE assets DROP COLUMN kind;
