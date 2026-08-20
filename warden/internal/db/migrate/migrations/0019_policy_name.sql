-- +goose Up
-- Optional per-scope policy name -> addressable as <name>@<asset-path>. Nullable:
-- unnamed policies keep id-only addressing. Unique per scope; NULLs never conflict.
ALTER TABLE request_policies ADD COLUMN name text;
ALTER TABLE request_policies ADD CONSTRAINT rp_name_canon CHECK (name IS NULL OR name ~ '^[a-z0-9_-]+$');
CREATE UNIQUE INDEX uq_policy_name_asset  ON request_policies(name, scope_asset_id)  WHERE name IS NOT NULL AND scope_asset_id  IS NOT NULL;
CREATE UNIQUE INDEX uq_policy_name_folder ON request_policies(name, scope_folder_id) WHERE name IS NOT NULL AND scope_folder_id IS NOT NULL;

-- +goose Down
DROP INDEX uq_policy_name_folder;
DROP INDEX uq_policy_name_asset;
ALTER TABLE request_policies DROP CONSTRAINT rp_name_canon;
ALTER TABLE request_policies DROP COLUMN name;
