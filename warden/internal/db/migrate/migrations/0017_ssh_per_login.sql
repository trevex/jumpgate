-- +goose Up
-- Move SSH auth from a per-asset auth_method to a per-login model. ssh_asset_config
-- keeps only the connection facts; each login's kind + secret ref lives in
-- ssh_asset_login. The composite FK (asset_id, secret_id) -> asset_secrets(asset_id, id)
-- makes it structurally impossible for one asset's login to reference another
-- asset's secret.
ALTER TABLE ssh_asset_config DROP CONSTRAINT IF EXISTS stored_key_needs_secret;
ALTER TABLE ssh_asset_config DROP COLUMN allowed_logins;
ALTER TABLE ssh_asset_config DROP COLUMN auth_method;
ALTER TABLE ssh_asset_config DROP COLUMN stored_secret_id;

ALTER TABLE asset_secrets ADD CONSTRAINT uq_asset_secret_asset_id UNIQUE (asset_id, id);

CREATE TABLE ssh_asset_login (
    asset_id  uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    login     text NOT NULL,
    kind      text NOT NULL CHECK (kind IN ('ca', 'password', 'key')),
    secret_id uuid,
    PRIMARY KEY (asset_id, login),
    CONSTRAINT ssh_login_secret_present CHECK (kind = 'ca' OR secret_id IS NOT NULL),
    CONSTRAINT ssh_login_secret_same_asset
        FOREIGN KEY (asset_id, secret_id) REFERENCES asset_secrets (asset_id, id) ON DELETE RESTRICT
);

-- +goose Down
DROP TABLE ssh_asset_login;
ALTER TABLE asset_secrets DROP CONSTRAINT uq_asset_secret_asset_id;
ALTER TABLE ssh_asset_config ADD COLUMN allowed_logins text[] NOT NULL DEFAULT '{}';
ALTER TABLE ssh_asset_config ADD COLUMN auth_method text NOT NULL DEFAULT 'ca-cert';
ALTER TABLE ssh_asset_config ADD COLUMN stored_secret_id uuid REFERENCES asset_secrets (id) ON DELETE RESTRICT;
