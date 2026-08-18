package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

func TestRoleBindingCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	role, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{Name: "op", ResourceType: "asset", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatal(err)
	}

	// valid: group -> role STANDING on folder
	rb, err := cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if rb.Msg.Id == "" {
		t.Fatal("empty binding id")
	}

	// invalid: two scopes set
	_, err = cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, ScopeAssetId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-scope binding = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// invalid: no subject
	_, err = cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no-subject binding = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// delete works
	if _, err := cat.DeleteRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.DeleteRoleBindingRequest{Id: rb.Msg.Id}), tok)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin binding = %v, want PermissionDenied", connect.CodeOf(err))
	}
}
