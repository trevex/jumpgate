-- +goose Up
ALTER TABLE ssh_asset_config ADD COLUMN host_public_key text NOT NULL DEFAULT '';
-- +goose Down
ALTER TABLE ssh_asset_config DROP COLUMN host_public_key;
