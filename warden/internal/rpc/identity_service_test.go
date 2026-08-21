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

// TestGroupGovernanceGating proves group membership/read/delete are gated at the
// group's folder scope (not global): a folder-scoped group-admin bound at folder
// `team` can manage a group homed in `team`, but not a group homed in `other`.
func TestGroupGovernanceGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Folders: demo, team (child of demo), other (all admin setup).
	demo, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "demo"}), atok))
	if err != nil {
		t.Fatalf("create demo: %v", err)
	}
	team, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "team", ParentId: demo.Msg.Folder.Id}), atok))
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	other, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "other"}), atok))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}

	// Groups: sre homed in team, x homed in other.
	sre, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre", FolderId: team.Msg.Folder.Id}), atok))
	if err != nil {
		t.Fatalf("create sre: %v", err)
	}
	x, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "x", FolderId: other.Msg.Folder.Id}), atok))
	if err != nil {
		t.Fatalf("create x: %v", err)
	}

	// A user to add.
	u, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "u@x", DisplayName: "U", Password: "password123",
	}), atok))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// dana: non-admin bound at folder `team` to a role carrying the group-mgmt caps.
	danaID := seedCapUser(t, pool, "dana@x", "danapass", `[]`) // creates the user
	bindScopedCap(t, pool, danaID, `["identity:group:add-member","identity:group:read","identity:group:delete"]`, uuidFromStr(t, team.Msg.Folder.Id), uuid.Nil)
	danatok := authClient(t, url, "dana@x", "danapass")

	// dana CAN add to sre (homed in team, where she holds the caps).
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: sre.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), danatok)); err != nil {
		t.Fatalf("dana AddUserToGroup(sre): %v", err)
	}
	// dana CAN list sre members.
	if _, err := id.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: sre.Msg.Group.Id}), danatok)); err != nil {
		t.Fatalf("dana ListGroupMembers(sre): %v", err)
	}

	// dana is DENIED on x (homed in other, where she holds no caps).
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: x.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), danatok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana AddUserToGroup(x) = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := id.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{GroupId: x.Msg.Group.Id}), danatok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana DeleteGroup(x) = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// admin (**) CAN do all, including on x.
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: x.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), atok)); err != nil {
		t.Fatalf("admin AddUserToGroup(x): %v", err)
	}
	if _, err := id.DeleteGroup(ctx, withToken(connect.NewRequest(&identityv1.DeleteGroupRequest{GroupId: x.Msg.Group.Id}), atok)); err != nil {
		t.Fatalf("admin DeleteGroup(x): %v", err)
	}
}

// TestResolveGroupAddressing pins ResolveGroup's uuid | bare-name (global) |
// <group>@<folder-path> resolution, its folder-scoped read gate, and the
// existence-hiding of a read-cap denial as NotFound.
func TestResolveGroupAddressing(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	prod, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), atok))
	if err != nil {
		t.Fatalf("create prod: %v", err)
	}
	prodID := prod.Msg.Folder.Id

	// A global group `sre` (no folder) and a folder-homed group `sre@prod`.
	global, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), atok))
	if err != nil {
		t.Fatalf("create global sre: %v", err)
	}
	scoped, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre", FolderId: prodID}), atok))
	if err != nil {
		t.Fatalf("create sre@prod: %v", err)
	}
	globalID := global.Msg.Group.Id
	scopedID := scoped.Msg.Group.Id

	resolve := func(tok, ref string) (*identityv1.ResolveGroupResponse, error) {
		r, err := id.ResolveGroup(ctx, withToken(connect.NewRequest(&identityv1.ResolveGroupRequest{Name: ref}), tok))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}

	// By the scoped group's uuid → its id.
	if m, err := resolve(atok, scopedID); err != nil {
		t.Fatalf("resolve by uuid: %v", err)
	} else if m.GroupId != scopedID {
		t.Fatalf("resolve by uuid = %q, want %q", m.GroupId, scopedID)
	}

	// Bare `sre` → the GLOBAL group.
	if m, err := resolve(atok, "sre"); err != nil {
		t.Fatalf("resolve bare: %v", err)
	} else if m.GroupId != globalID {
		t.Fatalf("resolve bare = %q, want global %q", m.GroupId, globalID)
	}

	// `sre@prod` → the PROD group; path echo `sre@prod`.
	if m, err := resolve(atok, "sre@prod"); err != nil {
		t.Fatalf("resolve sre@prod: %v", err)
	} else if m.GroupId != scopedID {
		t.Fatalf("resolve sre@prod = %q, want scoped %q", m.GroupId, scopedID)
	} else if m.Path != "sre@prod" {
		t.Fatalf("resolve sre@prod path = %q, want %q", m.Path, "sre@prod")
	}

	// `sre@nope` (unknown folder) → NotFound.
	if _, err := resolve(atok, "sre@nope"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("resolve sre@nope = %v, want NotFound", connect.CodeOf(err))
	}

	// dana: non-admin bound at prod with identity:group:read → resolve sre@prod succeeds.
	danaID := seedCapUser(t, pool, "dana@x", "danapass", `[]`)
	bindScopedCap(t, pool, danaID, `["identity:group:read"]`, uuidFromStr(t, prodID), uuid.Nil)
	danatok := authClient(t, url, "dana@x", "danapass")
	if m, err := resolve(danatok, "sre@prod"); err != nil {
		t.Fatalf("dana resolve sre@prod: %v", err)
	} else if m.GroupId != scopedID {
		t.Fatalf("dana resolve sre@prod = %q, want scoped %q", m.GroupId, scopedID)
	}

	// eve: non-admin with NO group caps → resolve sre@prod → NotFound (existence-hidden,
	// NOT PermissionDenied).
	seedCapUser(t, pool, "eve@x", "evepass1234", `[]`)
	evetok := authClient(t, url, "eve@x", "evepass1234")
	if _, err := resolve(evetok, "sre@prod"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("eve resolve sre@prod = %v, want NotFound", connect.CodeOf(err))
	}
}

func uuidFromStr(t *testing.T, s string) uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return u
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

// TestListGroupsScoped pins ListGroups as a visibility-scoped list: a global
// identity:group:read holder (incl. admin **) sees every group; a folder-scoped
// read holder sees only the groups homed in folders they can read; a caller with
// no group caps gets an empty list (not an error).
func TestListGroupsScoped(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	team, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "team"}), atok))
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	teamID := team.Msg.Folder.Id

	// sre homed in team; everyone is a global group (no folder).
	if _, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre", FolderId: teamID}), atok)); err != nil {
		t.Fatalf("create sre: %v", err)
	}
	if _, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "everyone"}), atok)); err != nil {
		t.Fatalf("create everyone: %v", err)
	}

	names := func(resp *identityv1.ListGroupsResponse) map[string]bool {
		m := map[string]bool{}
		for _, g := range resp.Groups {
			m[g.Name] = true
		}
		return m
	}

	// admin (**) sees both.
	ar, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), atok))
	if err != nil {
		t.Fatalf("admin ListGroups: %v", err)
	}
	an := names(ar.Msg)
	if !an["sre"] || !an["everyone"] {
		t.Fatalf("admin should see both, got %v", an)
	}

	// dana: folder-scoped identity:group:read at team → sees sre, not everyone.
	danaID := seedCapUser(t, pool, "dana@x", "danapass", `[]`)
	bindScopedCap(t, pool, danaID, `["identity:group:read"]`, uuidFromStr(t, teamID), uuid.Nil)
	danatok := authClient(t, url, "dana@x", "danapass")
	dr, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), danatok))
	if err != nil {
		t.Fatalf("dana ListGroups: %v", err)
	}
	dn := names(dr.Msg)
	if !dn["sre"] {
		t.Fatalf("dana should see sre, got %v", dn)
	}
	if dn["everyone"] {
		t.Fatalf("dana should NOT see global everyone, got %v", dn)
	}

	// eve: no group caps → empty list, no error.
	seedCapUser(t, pool, "eve@x", "evepass", `[]`)
	evetok := authClient(t, url, "eve@x", "evepass")
	er, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), evetok))
	if err != nil {
		t.Fatalf("eve ListGroups: %v", err)
	}
	if len(er.Msg.Groups) != 0 {
		t.Fatalf("eve should see no groups, got %d", len(er.Msg.Groups))
	}
}
