-- +goose Up
-- +goose StatementBegin

-- Drop the legacy per-asset trust config columns. Target trust now lives solely in
-- target_trust_anchors (established via the probe -> approve flow); workers validate
-- the observed target identity against a current active anchor, never these columns.
-- The one-shot 0007/0008/0009 migrations already carried any pinned value forward
-- into an approved migration-source anchor, so dropping these loses no trust.
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
