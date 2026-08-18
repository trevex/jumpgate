package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

// TestDeactivateBlocksAuthenticatedRPCs verifies that deactivating a user causes
// the interceptor to reject their otherwise-valid token: WhoAmI (which requires
// only an authenticated principal) starts returning Unauthenticated, and works
// again after reactivation.
func TestDeactivateBlocksAuthenticatedRPCs(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	authc := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create a non-admin user and obtain a token for them.
	u, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "dave@x", DisplayName: "Dave", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	utok := authClient(t, url, "dave@x", "password123")

	// Sanity: an authenticated call works with the fresh token.
	if _, err := authc.WhoAmI(ctx, withToken(connect.NewRequest(&authv1.WhoAmIRequest{}), utok)); err != nil {
		t.Fatalf("whoami before deactivate: %v", err)
	}

	// Deactivate (as admin).
	if _, err := id.DeactivateUser(ctx, withToken(connect.NewRequest(&identityv1.DeactivateUserRequest{UserId: u.Msg.User.Id}), tok)); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// The SAME token is now rejected at lookup -> Unauthenticated.
	_, err = authc.WhoAmI(ctx, withToken(connect.NewRequest(&authv1.WhoAmIRequest{}), utok))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("whoami while deactivated = %v, want Unauthenticated", connect.CodeOf(err))
	}

	// Reactivate restores access with the same token.
	if _, err := id.ReactivateUser(ctx, withToken(connect.NewRequest(&identityv1.ReactivateUserRequest{UserId: u.Msg.User.Id}), tok)); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := authc.WhoAmI(ctx, withToken(connect.NewRequest(&authv1.WhoAmIRequest{}), utok)); err != nil {
		t.Fatalf("whoami after reactivate: %v", err)
	}
}

// TestDeleteGroupCascades verifies DeleteGroup removes the group along with its
// role bindings and memberships via ON DELETE CASCADE.
func TestDeleteGroupCascades(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "doomed"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	// A user member of the group.
	u, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "erin@x", DisplayName: "Erin", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: g.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add user to group: %v", err)
	}
	// A role binding with the group as subject.
	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "op", ResourceType: "asset", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	// Delete the group.
	if _, err := id.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{GroupId: g.Msg.Group.Id}), tok)); err != nil {
		t.Fatalf("delete group: %v", err)
	}

	// Binding with this group as subject is gone.
	lb, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{SubjectGroupId: g.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(lb.Msg.Bindings) != 0 {
		t.Fatalf("bindings after DeleteGroup = %d, want 0", len(lb.Msg.Bindings))
	}
	// The group no longer appears in ListGroups.
	groups, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), tok))
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	for _, gg := range groups.Msg.Groups {
		if gg.Id == g.Msg.Group.Id {
			t.Fatalf("group %s still present after delete", gg.Id)
		}
	}

	// Deleting a non-existent group is a no-op.
	if _, err := id.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{GroupId: g.Msg.Group.Id}), tok)); err != nil {
		t.Fatalf("delete missing group not a no-op: %v", err)
	}
}

// TestDeleteUserCascades verifies DeleteUser removes the user along with their
// memberships and role bindings via ON DELETE CASCADE.
func TestDeleteUserCascades(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	u, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "frank@x", DisplayName: "Frank", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "team"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: g.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add user to group: %v", err)
	}
	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "op", ResourceType: "asset", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectUserId: u.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("create binding: %v", err)
	}

	// Delete the user.
	if _, err := id.DeleteUser(ctx, withToken(connect.NewRequest(&identityv1.DeleteUserRequest{UserId: u.Msg.User.Id}), tok)); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// Their user-subject binding is gone.
	lb, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{SubjectUserId: u.Msg.User.Id}), tok))
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(lb.Msg.Bindings) != 0 {
		t.Fatalf("bindings after DeleteUser = %d, want 0", len(lb.Msg.Bindings))
	}
	// Their group membership is gone.
	members, err := id.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members.Msg.Users) != 0 {
		t.Fatalf("members after DeleteUser = %d, want 0", len(members.Msg.Users))
	}
	// GetUser now reports NotFound.
	if _, err := id.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: u.Msg.User.Id}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("get deleted user = %v, want NotFound", connect.CodeOf(err))
	}
}
