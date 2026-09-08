-- +goose Up
-- +goose StatementBegin

-- Drop the legacy per-asset trust config columns. Target trust now lives solely in
-- target_trust_anchors (established via the probe -> approve flow); workers validate
-- the observed target identity against a current active anchor, never these columns.
-- The version-11 Go migration (migrations/legacy_pins.go) runs immediately before this
-- one and carries every valid pinned value forward into an approved migration-source
-- anchor, so dropping these columns loses no trust.
ALTER TABLE ssh_asset_config DROP COLUMN host_public_key;
ALTER TABLE postgres_asset_config DROP COLUMN target_server_ca;
ALTER TABLE rdp_asset_config DROP COLUMN target_server_ca;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE ssh_asset_config ADD COLUMN host_public_key text DEFAULT ''::text NOT NULL;
ALTER TABLE postgres_asset_config ADD COLUMN target_server_ca text DEFAULT ''::text NOT NULL;
ALTER TABLE rdp_asset_config ADD COLUMN target_server_ca text DEFAULT ''::text NOT NULL;

-- +goose StatementEnd
