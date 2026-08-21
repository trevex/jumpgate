package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

func adminToken(t *testing.T, url string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	resp, err := c.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "supersecret"}))
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	return resp.Msg.Token
}

func withToken[T any](req *connect.Request[T], tok string) *connect.Request[T] {
	req.Header().Set("Authorization", "Bearer "+tok)
	return req
}

// TestManagementIsCapabilityOnly proves management authz is capability-only:
// there is no is_admin path. A freshly-created user with NO role bindings is
// PermissionDenied on a management RPC, while the bootstrap/harness admin (who is
// admitted ONLY by holding `**` via a global role binding) is allowed.
func TestManagementIsCapabilityOnly(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)  // admin=true seeds `**` globally
	seedUser(t, pool, "nobody@x", "nobodypass", false) // no caps, no bindings
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Capless user → PermissionDenied on a management RPC.
	nobodyTok := authClient(t, url, "nobody@x", "nobodypass")
	_, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "x1@x", DisplayName: "X1", Password: "password123",
	}), nobodyTok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("capless create code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Admin holding `**` → allowed.
	adminTok := adminToken(t, url)
	if _, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "x2@x", DisplayName: "X2", Password: "password123",
	}), adminTok)); err != nil {
		t.Fatalf("admin create: %v", err)
	}
}

func TestUsersCRUDRequiresAdmin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// No token → not allowed
	_, err := c.CreateUser(ctx, connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "bob@x", DisplayName: "Bob", Password: "password123",
	}))
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated && code != connect.CodePermissionDenied {
		t.Fatalf("anon create code = %v, want Unauthenticated/PermissionDenied", code)
	}

	created, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "bob@x", DisplayName: "Bob", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Msg.User.Email != "bob@x" {
		t.Fatalf("created: %+v", created.Msg)
	}

	got, err := c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: created.Msg.User.Id}), tok))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Msg.User.Id != created.Msg.User.Id {
		t.Fatalf("get mismatch")
	}

	_, err = c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: "00000000-0000-0000-0000-000000000000"}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("get unknown code = %v, want NotFound", connect.CodeOf(err))
	}

	list, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Msg.Users) < 2 {
		t.Fatalf("list returned %d users, want >=2", len(list.Msg.Users))
	}
}

// seedCapUser creates a non-admin local user bound GLOBALLY to a fresh role
// carrying the given capabilities, and returns the user id. It mirrors the
// admin path in seedUser but with a scoped capability set instead of `**`.
func seedCapUser(t *testing.T, pool *pgxpool.Pool, email, pw string, capsJSON string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "role-" + uuid.NewString(), Capabilities: []byte(capsJSON)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        role.ID,
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestIdentityCapabilityGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedCapUser(t, pool, "reader@x", "readerpass", `["identity:user:read"]`)
	seedCapUser(t, pool, "groupmgr@x", "groupmgrpass", `["identity:group:add-member","identity:group:read"]`)

	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	adminTok := adminToken(t, url)
	readerTok := authClient(t, url, "reader@x", "readerpass")
	groupmgrTok := authClient(t, url, "groupmgr@x", "groupmgrpass")

	// admin (**) can do everything: create a user and a group to operate on.
	createdUser, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "target@x", DisplayName: "Target", Password: "password123",
	}), adminTok))
	if err != nil {
		t.Fatalf("admin create user: %v", err)
	}
	createdGroup, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "gcap",
	}), adminTok))
	if err != nil {
		t.Fatalf("admin create group: %v", err)
	}

	// reader holds identity:user:read globally → CAN read.
	if _, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 50}), readerTok)); err != nil {
		t.Fatalf("reader ListUsers: %v", err)
	}
	if _, err := c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: createdUser.Msg.User.Id}), readerTok)); err != nil {
		t.Fatalf("reader GetUser: %v", err)
	}

	// reader lacks identity:user:create → PermissionDenied.
	_, err = c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "nope@x", DisplayName: "Nope", Password: "password123",
	}), readerTok))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Fatalf("reader CreateUser code = %v, want PermissionDenied", code)
	}

	// reader lacks identity:group:create → PermissionDenied.
	_, err = c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "nope-group"}), readerTok))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Fatalf("reader CreateGroup code = %v, want PermissionDenied", code)
	}

	// groupmgr holds identity:group:add-member → CAN add a user to the group.
	if _, err := c.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: createdGroup.Msg.Group.Id, UserId: createdUser.Msg.User.Id,
	}), groupmgrTok)); err != nil {
		t.Fatalf("groupmgr AddUserToGroup: %v", err)
	}

	// groupmgr lacks identity:group:delete → PermissionDenied.
	_, err = c.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{
		GroupId: createdGroup.Msg.Group.Id,
	}), groupmgrTok))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Fatalf("groupmgr DeleteGroup code = %v, want PermissionDenied", code)
	}

	// admin (**) can delete the group.
	if _, err := c.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{
		GroupId: createdGroup.Msg.Group.Id,
	}), adminTok)); err != nil {
		t.Fatalf("admin DeleteGroup: %v", err)
	}
}

func TestGetUserMalformedUUID(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	_, err := c.GetUser(context.Background(), withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: "not-a-uuid"}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed uuid code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// TestGroupFolderUniqueness pins per-folder group name uniqueness.
func TestGroupFolderUniqueness(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mkFolder := func(name string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.GetFolder().GetId()
	}
	mkGroup := func(name, folderID string) error {
		_, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: name, FolderId: folderID}), tok))
		return err
	}
	prod := mkFolder("prod")
	dev := mkFolder("dev")
	if err := mkGroup("sre", ""); err != nil {
		t.Fatalf("global sre: %v", err)
	}
	if err := mkGroup("sre", ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup global = %v", connect.CodeOf(err))
	}
	if err := mkGroup("sre", prod); err != nil {
		t.Fatalf("sre@prod: %v", err)
	}
	if err := mkGroup("sre", dev); err != nil {
		t.Fatalf("sre@dev: %v", err)
	}
	if err := mkGroup("sre", prod); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup sre@prod = %v", connect.CodeOf(err))
	}
	if err := mkGroup("Bad Name", ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad name = %v", connect.CodeOf(err))
	}
}
