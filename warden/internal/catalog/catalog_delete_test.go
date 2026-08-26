package catalog_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestDeleteAssetCascadesGovernanceViaFK asserts that deleting an asset row directly
// (bypassing the handler's explicit governance-row deletes) tears down its asset-scoped
// role_binding, request_policy, AND the policy's subject via DB ON DELETE CASCADE.
func TestDeleteAssetCascadesGovernanceViaFK(t *testing.T) {
	env := newCatalogTestEnv(t)
	ctx := context.Background()
	folderID := env.createFolder(t, "prod")
	assetIDStr := env.createSSHAsset(t, folderID, "pg", "app", []byte("pw"))
	env.bindRoleToAsset(t, assetIDStr) // asset-scoped role_binding

	// Seed a request_policy scoped to the asset plus a policy subject.
	var roleID, policyID string
	if err := env.pool.QueryRow(ctx,
		`INSERT INTO roles(name) VALUES('p-'||substr(md5(random()::text),1,8)) RETURNING id`,
	).Scan(&roleID); err != nil {
		t.Fatalf("insert role: %v", err)
	}
	if err := env.pool.QueryRow(ctx,
		`INSERT INTO request_policies(role_id, scope_asset_id) VALUES($1, $2) RETURNING id`,
		roleID, assetIDStr,
	).Scan(&policyID); err != nil {
		t.Fatalf("insert request_policy: %v", err)
	}
	if _, err := env.pool.Exec(ctx,
		`INSERT INTO request_policy_subjects(policy_id, subject_user_id, kind) VALUES($1, $2, 'requester')`,
		policyID, env.userID,
	); err != nil {
		t.Fatalf("insert request_policy_subject: %v", err)
	}

	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		t.Fatalf("parse asset id: %v", err)
	}
	q := sqlc.New(env.pool)
	if err := q.DeleteAsset(ctx, assetID); err != nil {
		t.Fatalf("DeleteAsset (direct): %v", err)
	}

	if n := env.count(t, "SELECT count(*) FROM role_bindings WHERE scope_asset_id=$1", assetIDStr); n != 0 {
		t.Fatalf("role_bindings = %d, want 0 (FK cascade)", n)
	}
	if n := env.count(t, "SELECT count(*) FROM request_policies WHERE scope_asset_id=$1", assetIDStr); n != 0 {
		t.Fatalf("request_policies = %d, want 0 (FK cascade)", n)
	}
	if n := env.count(t, "SELECT count(*) FROM request_policy_subjects WHERE policy_id=$1", policyID); n != 0 {
		t.Fatalf("request_policy_subjects = %d, want 0 (FK cascade)", n)
	}
}

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
