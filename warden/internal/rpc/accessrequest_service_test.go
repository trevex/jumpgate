package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

func TestResolveApproval(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ar := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Create a role.
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "db-admin", ResourceType: "asset", Capabilities: []string{"db:read", "db:write"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	// Create a folder + asset.
	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	asset, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folder.Msg.Folder.Id, Name: "pg-prod",
	}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assetID := asset.Msg.Asset.Id

	// Create a role-default request policy, required=2.
	if _, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		RequiredApprovals: 2,
	}), tok)); err != nil {
		t.Fatalf("create request policy: %v", err)
	}

	// non-admin ResolveApproval → PermissionDenied
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
		RoleId: roleID, AssetId: assetID,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin ResolveApproval = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// ResolveApproval for role with policy → requestable=true, required=2
	res, err := ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
		RoleId:  roleID,
		AssetId: assetID,
	}), tok))
	if err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	if !res.Msg.Requestable {
		t.Fatal("want requestable=true")
	}
	if res.Msg.RequiredApprovals != 2 {
		t.Fatalf("required_approvals = %d, want 2", res.Msg.RequiredApprovals)
	}

	// Create a second role with no policy → ResolveApproval requestable=false
	role2, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "no-rule-role", ResourceType: "asset", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role2: %v", err)
	}
	res2, err := ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
		RoleId:  role2.Msg.Role.Id,
		AssetId: assetID,
	}), tok))
	if err != nil {
		t.Fatalf("resolve approval (no rule): %v", err)
	}
	if res2.Msg.Requestable {
		t.Fatal("want requestable=false for role with no rule")
	}
}
