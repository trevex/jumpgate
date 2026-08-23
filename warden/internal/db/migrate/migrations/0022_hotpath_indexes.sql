-- +goose Up
-- Hot-path indexes for query filters that currently seq-scan.

-- RevokeActiveGrantsForRole filters access_grants WHERE role_id = $1 on every
-- DeleteRole; the table is append-only/unbounded and only had a partial index on
-- subject_user_id.
CREATE INDEX IF NOT EXISTS idx_access_grants_role ON access_grants (role_id);

-- catalog_names(folder_id) and catalog_names(asset_id) are ON DELETE CASCADE FK
-- children with no index (unindexed-FK seq-scan on every folder/asset delete;
-- also filtered by UpdateFolderCatalogName / UpdateAssetCatalogName). The columns
-- are nullable (exactly one is set per row), so partial indexes are smaller.
CREATE INDEX IF NOT EXISTS idx_catalog_names_folder ON catalog_names (folder_id) WHERE folder_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_catalog_names_asset  ON catalog_names (asset_id)  WHERE asset_id  IS NOT NULL;

-- Pending-request-by-scope approval scans: ListPendingRequestsByAsset /
-- ListPendingRequestsByRole filter status='pending' AND asset_id/role_id = $1.
CREATE INDEX IF NOT EXISTS idx_access_requests_pending_asset ON access_requests (asset_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_access_requests_pending_role  ON access_requests (role_id)  WHERE status = 'pending';

-- +goose Down
DROP INDEX IF EXISTS idx_access_grants_role;
DROP INDEX IF EXISTS idx_catalog_names_folder;
DROP INDEX IF EXISTS idx_catalog_names_asset;
DROP INDEX IF EXISTS idx_access_requests_pending_asset;
DROP INDEX IF EXISTS idx_access_requests_pending_role;
