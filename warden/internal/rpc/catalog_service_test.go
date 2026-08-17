package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

func TestCatalogAdminCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "nope"}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateFolder = %v, want PermissionDenied", connect.CodeOf(err))
	}

	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: "pg-prod"}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assets, err := c.ListAssetsByFolder(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsByFolderRequest{FolderId: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(assets.Msg.Assets) != 1 || assets.Msg.Assets[0].Id != a.Msg.Asset.Id {
		t.Fatalf("list assets mismatch: %+v", assets.Msg.Assets)
	}
	r, err := c.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{Name: "readonly", ResourceType: "asset", Capabilities: []string{"read"}}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if r.Msg.Role.Name != "readonly" || len(r.Msg.Role.Capabilities) != 1 {
		t.Fatalf("role: %+v", r.Msg.Role)
	}
	roles, err := c.ListRoles(ctx, withToken(connect.NewRequest(&catalogv1.ListRolesRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles.Msg.Roles) < 1 {
		t.Fatalf("want >=1 role")
	}
	folders, err := c.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list folders: %v", err)
	}
	if len(folders.Msg.Folders) < 1 {
		t.Fatalf("want >=1 folder")
	}
}
