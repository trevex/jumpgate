package rpc_test

import (
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

func TestDeleteAssetCascades(t *testing.T) {
	env := newCatalogTestEnv(t)
	folderID := env.createFolder(t, "prod")
	assetID := env.createSSHAsset(t, folderID, "pg", "app", []byte("pw")) // ca+password; seals a secret
	env.bindRoleToAsset(t, assetID)                                       // an asset-scoped binding

	if _, err := env.catalog.DeleteAsset(env.adminCtx, connect.NewRequest(&catalogv1.DeleteAssetRequest{AssetId: assetID})); err != nil {
		t.Fatalf("DeleteAsset: %v", err)
	}
	if n := env.count(t, "SELECT count(*) FROM asset_secrets WHERE asset_id=$1", assetID); n != 0 {
		t.Fatalf("asset_secrets = %d, want 0", n)
	}
	if n := env.count(t, "SELECT count(*) FROM ssh_asset_login WHERE asset_id=$1", assetID); n != 0 {
		t.Fatalf("ssh_asset_login = %d, want 0", n)
	}
	if n := env.count(t, "SELECT count(*) FROM role_bindings WHERE scope_asset_id=$1", assetID); n != 0 {
		t.Fatalf("bindings = %d, want 0", n)
	}
	_, err := env.catalog.ResolveAsset(env.adminCtx, connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: assetID}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}

func TestDeleteFolderBlocksWhenNonEmpty(t *testing.T) {
	env := newCatalogTestEnv(t)
	parent := env.createFolder(t, "prod")
	env.createChildFolder(t, "db", parent) // child folder makes it non-empty

	_, err := env.catalog.DeleteFolder(env.adminCtx, connect.NewRequest(&catalogv1.DeleteFolderRequest{FolderId: parent}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition for non-empty folder, got %v", err)
	}
}

func TestDeleteFolderSucceedsWhenEmpty(t *testing.T) {
	env := newCatalogTestEnv(t)
	f := env.createFolder(t, "empty")
	if _, err := env.catalog.DeleteFolder(env.adminCtx, connect.NewRequest(&catalogv1.DeleteFolderRequest{FolderId: f})); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	_, err := env.catalog.ResolveFolder(env.adminCtx, connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "empty"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}
