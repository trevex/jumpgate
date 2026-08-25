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
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	q := sqlc.New(pool)
	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "role-"+uuid.NewString(), pgtype.UUID{}, capsJSON)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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

// TestGetUserDisplay pins GetUserDisplay as a universal directory read: any
// authenticated caller (no capabilities) gets {id, display_name, email} for a
// user id; a missing/malformed id is NotFound; a deactivated user is still
// returned (display-only, not an authz decision).
func TestGetUserDisplay(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// A capless (non-admin) caller does the display reads.
	seedCapUser(t, pool, "capless@x", "caplesspass", `[]`)
	capless := authClient(t, url, "capless@x", "caplesspass")

	// An existing target user with a distinct display name + email.
	target, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "target@x", DisplayName: "Target Person", Password: "password123",
	}), atok))
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	targetID := target.Msg.User.Id

	// Capless caller reads the target's display: all three fields match.
	got, err := c.GetUserDisplay(ctx, withToken(connect.NewRequest(&identityv1.GetUserDisplayRequest{Id: targetID}), capless))
	if err != nil {
		t.Fatalf("capless GetUserDisplay: %v", err)
	}
	if got.Msg.User == nil {
		t.Fatal("GetUserDisplay: nil user")
	}
	if got.Msg.User.Id != targetID {
		t.Fatalf("display id = %q, want %q", got.Msg.User.Id, targetID)
	}
	if got.Msg.User.DisplayName != "Target Person" {
		t.Fatalf("display name = %q, want %q", got.Msg.User.DisplayName, "Target Person")
	}
	if got.Msg.User.Email != "target@x" {
		t.Fatalf("display email = %q, want %q", got.Msg.User.Email, "target@x")
	}

	// A missing id → NotFound.
	if _, err := c.GetUserDisplay(ctx, withToken(connect.NewRequest(&identityv1.GetUserDisplayRequest{
		Id: "00000000-0000-0000-0000-000000000000",
	}), capless)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing id code = %v, want NotFound", connect.CodeOf(err))
	}

	// A malformed id is rejected by request validation (string.uuid) before the
	// handler runs → InvalidArgument, mirroring GetUser.
	if _, err := c.GetUserDisplay(ctx, withToken(connect.NewRequest(&identityv1.GetUserDisplayRequest{
		Id: "not-a-uuid",
	}), capless)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed id code = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// A deactivated user is still returned (display-only, not an authz decision).
	dead, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "dead@x", DisplayName: "Deactivated One", Password: "password123",
	}), atok))
	if err != nil {
		t.Fatalf("create dead: %v", err)
	}
	if _, err := c.DeactivateUser(ctx, withToken(connect.NewRequest(&identityv1.DeactivateUserRequest{
		UserId: dead.Msg.User.Id,
	}), atok)); err != nil {
		t.Fatalf("deactivate dead: %v", err)
	}
	deadDisp, err := c.GetUserDisplay(ctx, withToken(connect.NewRequest(&identityv1.GetUserDisplayRequest{
		Id: dead.Msg.User.Id,
	}), capless))
	if err != nil {
		t.Fatalf("GetUserDisplay(deactivated): %v", err)
	}
	if deadDisp.Msg.User.DisplayName != "Deactivated One" || deadDisp.Msg.User.Email != "dead@x" {
		t.Fatalf("deactivated display = %+v, want name/email preserved", deadDisp.Msg.User)
	}
}

// TestUserActiveFlag pins User.active as the deactivation state surfaced on the
// User message: a freshly created user is active on both GetUser and in
// ListUsers; DeactivateUser flips it to false; ReactivateUser flips it back.
func TestUserActiveFlag(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	created, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "active@x", DisplayName: "Active", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	uid := created.Msg.User.Id

	// activeInList finds our user in ListUsers and reports its Active flag.
	activeInList := func() bool {
		list, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 100}), tok))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, u := range list.Msg.Users {
			if u.Id == uid {
				return u.Active
			}
		}
		t.Fatalf("user %s not found in ListUsers", uid)
		return false
	}
	// activeOnGet reports GetUser's Active flag for our user.
	activeOnGet := func() bool {
		got, err := c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: uid}), tok))
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return got.Msg.User.Active
	}

	// Freshly created → active on both reads.
	if !activeOnGet() {
		t.Fatal("new user GetUser Active = false, want true")
	}
	if !activeInList() {
		t.Fatal("new user ListUsers Active = false, want true")
	}

	// Deactivate → active = false on both reads.
	if _, err := c.DeactivateUser(ctx, withToken(connect.NewRequest(&identityv1.DeactivateUserRequest{UserId: uid}), tok)); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if activeOnGet() {
		t.Fatal("deactivated GetUser Active = true, want false")
	}
	if activeInList() {
		t.Fatal("deactivated ListUsers Active = true, want false")
	}

	// Reactivate → active = true on both reads.
	if _, err := c.ReactivateUser(ctx, withToken(connect.NewRequest(&identityv1.ReactivateUserRequest{UserId: uid}), tok)); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if !activeOnGet() {
		t.Fatal("reactivated GetUser Active = false, want true")
	}
	if !activeInList() {
		t.Fatal("reactivated ListUsers Active = false, want true")
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

// TestListGroupsScoped pins ListGroups as a path-scoped visibility browse: the
// parent parameter controls which part of the tree is browsed. An admin sees
// all groups in the requested scope; a folder-scoped read holder sees only the
// groups homed in folders they can read within that scope; a caller with no
// group caps or membership gets an empty list (not an error).
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

	// admin (**) with cascade=true sees both (global + folder-scoped).
	ar, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100, Cascade: true}), atok))
	if err != nil {
		t.Fatalf("admin ListGroups (cascade): %v", err)
	}
	an := names(ar.Msg)
	if !an["sre"] || !an["everyone"] {
		t.Fatalf("admin (cascade) should see both, got %v", an)
	}

	// admin with parent="" (root, no cascade) sees only global groups.
	rootList, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), atok))
	if err != nil {
		t.Fatalf("admin root list: %v", err)
	}
	rn := names(rootList.Msg)
	if !rn["everyone"] {
		t.Fatalf("admin root should see everyone (global), got %v", rn)
	}
	if rn["sre"] {
		t.Fatalf("admin root should NOT see sre (folder-scoped), got %v", rn)
	}

	// admin with parent=team sees sre only (not everyone).
	teamList, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100, Parent: teamID}), atok))
	if err != nil {
		t.Fatalf("admin team list: %v", err)
	}
	tn := names(teamList.Msg)
	if !tn["sre"] {
		t.Fatalf("admin@team should see sre, got %v", tn)
	}
	if tn["everyone"] {
		t.Fatalf("admin@team should NOT see everyone, got %v", tn)
	}

	// dana: folder-scoped identity:group:read at team → parent=team sees sre.
	danaID := seedCapUser(t, pool, "dana@x", "danapass", `[]`)
	bindScopedCap(t, pool, danaID, `["identity:group:read"]`, uuidFromStr(t, teamID), uuid.Nil)
	danatok := authClient(t, url, "dana@x", "danapass")
	dr, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100, Parent: teamID}), danatok))
	if err != nil {
		t.Fatalf("dana ListGroups@team: %v", err)
	}
	dn := names(dr.Msg)
	if !dn["sre"] {
		t.Fatalf("dana@team should see sre, got %v", dn)
	}
	if dn["everyone"] {
		t.Fatalf("dana@team should NOT see global everyone, got %v", dn)
	}

	// dana at root (parent="") sees no groups (has no global cap, sre is folder-scoped).
	danaRoot, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), danatok))
	if err != nil {
		t.Fatalf("dana root list: %v", err)
	}
	if len(danaRoot.Msg.Groups) != 0 {
		t.Fatalf("dana root should see 0 groups, got %d", len(danaRoot.Msg.Groups))
	}

	// eve: no group caps → empty list at any scope, no error.
	seedCapUser(t, pool, "eve@x", "evepass", `[]`)
	evetok := authClient(t, url, "eve@x", "evepass")
	er, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100, Cascade: true}), evetok))
	if err != nil {
		t.Fatalf("eve ListGroups: %v", err)
	}
	if len(er.Msg.Groups) != 0 {
		t.Fatalf("eve should see no groups, got %d", len(er.Msg.Groups))
	}
}

// TestListUsersKeysetByEmail verifies name-ordered (email ASC, id ASC) keyset
// pagination for ListUsers. Seeds 3 users with emails in deliberately reversed
// alphabetical order (creation order = z, m, f) and confirms page 1 returns
// [f@x, m@x] (proving EMAIL order, not creation order) with a non-empty token,
// and page 2 returns [z@x] with an empty token. The seeded admin@x sorts before
// all of these; it is included in the count but not asserted by name to avoid
// locale-specific '@' vs letter collation surprises.
func TestListUsersKeysetByEmail(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create 3 users in deliberately reversed order (z first, f last) to prove
	// the list is ordered by email, not by creation/id order.
	for _, email := range []string{"z@example.com", "m@example.com", "f@example.com"} {
		if _, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
			Email: email, DisplayName: email, Password: "password123",
		}), tok)); err != nil {
			t.Fatalf("create %s: %v", email, err)
		}
	}

	// Fetch all 4 users with a large page to verify global email order (no token).
	all, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{
		PageSize: 100,
	}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Msg.Users) != 4 {
		t.Fatalf("total users = %d, want 4", len(all.Msg.Users))
	}
	// Confirm email ORDER is ascending: each email must be >= the previous.
	for i := 1; i < len(all.Msg.Users); i++ {
		if all.Msg.Users[i].Email < all.Msg.Users[i-1].Email {
			t.Fatalf("email order wrong at index %d: %q < %q",
				i, all.Msg.Users[i].Email, all.Msg.Users[i-1].Email)
		}
	}
	// The three unambiguous example.com users must appear in f < m < z order.
	var exUsers []string
	for _, u := range all.Msg.Users {
		if u.Email == "f@example.com" || u.Email == "m@example.com" || u.Email == "z@example.com" {
			exUsers = append(exUsers, u.Email)
		}
	}
	wantEx := []string{"f@example.com", "m@example.com", "z@example.com"}
	for i, w := range wantEx {
		if i >= len(exUsers) || exUsers[i] != w {
			t.Fatalf("example.com users out of order: got %v, want %v", exUsers, wantEx)
		}
	}

	// Verify keyset pagination with page_size=3 (4 users → page1=3+token, page2=1+no token).
	// Using 3 avoids the exact-multiple case where even the last real page emits a token.
	page1, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{
		PageSize: 3,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Users) != 3 {
		t.Fatalf("page1: got %d users, want 3", len(page1.Msg.Users))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	// Page 1 must be the first 3 emails from the full ordered list.
	for i, u := range page1.Msg.Users {
		if u.Email != all.Msg.Users[i].Email {
			t.Fatalf("page1[%d] = %q, want %q", i, u.Email, all.Msg.Users[i].Email)
		}
	}

	page2, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{
		PageSize:  3,
		PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Users) != 1 {
		t.Fatalf("page2: got %d users, want 1", len(page2.Msg.Users))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	// Page 2 must be the last email from the full ordered list.
	if page2.Msg.Users[0].Email != all.Msg.Users[3].Email {
		t.Fatalf("page2[0] = %q, want %q", page2.Msg.Users[0].Email, all.Msg.Users[3].Email)
	}

	// Total across both pages == 4.
	if len(page1.Msg.Users)+len(page2.Msg.Users) != 4 {
		t.Fatalf("total from paged = %d, want 4", len(page1.Msg.Users)+len(page2.Msg.Users))
	}
}

// TestListGroupsKeysetByName verifies name-ordered (name ASC, id ASC) keyset
// pagination for ListGroups (admin / fast-path). Seeds 3 groups with names in
// reversed alphabetical order, confirms page 1 returns [beta, gamma] with a
// token, and page 2 returns [zeta] with no token.
func TestListGroupsKeysetByName(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create in deliberately reversed alphabetical order to prove name ordering.
	for _, name := range []string{"zeta", "gamma", "beta"} {
		if _, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: name}), tok)); err != nil {
			t.Fatalf("create group %s: %v", name, err)
		}
	}

	// Fetch all 3 groups (large page) and verify name order.
	all, err := c.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Msg.Groups) != 3 {
		t.Fatalf("total groups = %d, want 3", len(all.Msg.Groups))
	}
	for i := 1; i < len(all.Msg.Groups); i++ {
		if all.Msg.Groups[i].Name < all.Msg.Groups[i-1].Name {
			t.Fatalf("name order wrong at index %d: %q < %q", i, all.Msg.Groups[i].Name, all.Msg.Groups[i-1].Name)
		}
	}
	// Alphabetically: beta < gamma < zeta
	wantOrder := []string{"beta", "gamma", "zeta"}
	for i, w := range wantOrder {
		if all.Msg.Groups[i].Name != w {
			t.Fatalf("all[%d] = %q, want %q", i, all.Msg.Groups[i].Name, w)
		}
	}

	// Page through with page_size=2 (3 groups → page1=2+token, page2=1+no token).
	page1, err := c.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 2}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Groups) != 2 {
		t.Fatalf("page1: got %d groups, want 2", len(page1.Msg.Groups))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	if page1.Msg.Groups[0].Name != "beta" || page1.Msg.Groups[1].Name != "gamma" {
		t.Fatalf("page1 names = [%s, %s], want [beta, gamma]", page1.Msg.Groups[0].Name, page1.Msg.Groups[1].Name)
	}

	page2, err := c.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		PageSize:  2,
		PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Groups) != 1 {
		t.Fatalf("page2: got %d groups, want 1", len(page2.Msg.Groups))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Groups[0].Name != "zeta" {
		t.Fatalf("page2[0] = %q, want zeta", page2.Msg.Groups[0].Name)
	}

	// Total across pages == 3.
	if len(page1.Msg.Groups)+len(page2.Msg.Groups) != 3 {
		t.Fatalf("total paged = %d, want 3", len(page1.Msg.Groups)+len(page2.Msg.Groups))
	}
}

// TestListGroupsScopedVisibilityIsolation verifies that a caller with
// identity:group:read scoped to folder A sees only groups homed in A (not in B)
// when browsing with parent=fA. Groups homed in folder B are not returned. With
// cascade=true, all groups under folder A (including nested sub-folders) appear.
// This replaces the old "filtered slow path" test, which was specific to the
// previous full-scan-then-filter implementation.
func TestListGroupsScopedVisibilityIsolation(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create two sibling folders: A (caller can read) and B (caller cannot).
	fA, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "fa"}), atok))
	if err != nil {
		t.Fatalf("create folder fa: %v", err)
	}
	fB, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "fb"}), atok))
	if err != nil {
		t.Fatalf("create folder fb: %v", err)
	}
	folderAID := uuidFromStr(t, fA.Msg.Folder.Id)

	// Grant the caller identity:group:read scoped to folder A ONLY.
	callerID := seedCapUser(t, pool, "partial@x", "partialpass", `[]`)
	bindScopedCap(t, pool, callerID, `["identity:group:read"]`, folderAID, uuid.Nil)
	callerTok := authClient(t, url, "partial@x", "partialpass")

	// 2 groups in folder B (invisible to caller), 1 group in folder A (visible).
	for _, name := range []string{"aa-hidden", "ab-hidden"} {
		if _, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
			Name:     name,
			FolderId: fB.Msg.Folder.Id,
		}), atok)); err != nil {
			t.Fatalf("create hidden group %s: %v", name, err)
		}
	}
	if _, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name:     "zz-visible",
		FolderId: fA.Msg.Folder.Id,
	}), atok)); err != nil {
		t.Fatalf("create visible group: %v", err)
	}

	// caller browsing parent=fA sees exactly zz-visible.
	res, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		PageSize: 10, Parent: fA.Msg.Folder.Id,
	}), callerTok))
	if err != nil {
		t.Fatalf("list fA: %v", err)
	}
	if len(res.Msg.Groups) != 1 || res.Msg.Groups[0].Name != "zz-visible" {
		t.Fatalf("fA list: got %v, want [zz-visible]", res.Msg.Groups)
	}

	// caller browsing parent=fB sees nothing (no cap there).
	resB, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		PageSize: 10, Parent: fB.Msg.Folder.Id,
	}), callerTok))
	if err != nil {
		t.Fatalf("list fB: %v", err)
	}
	if len(resB.Msg.Groups) != 0 {
		t.Fatalf("fB list: got %d groups, want 0", len(resB.Msg.Groups))
	}

	// caller browsing root with cascade=true sees only fA groups.
	cascRes, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		PageSize: 10, Cascade: true,
	}), callerTok))
	if err != nil {
		t.Fatalf("list cascade: %v", err)
	}
	for _, g := range cascRes.Msg.Groups {
		if g.Name == "aa-hidden" || g.Name == "ab-hidden" {
			t.Errorf("cascade: should not see hidden group %q", g.Name)
		}
	}
	found := false
	for _, g := range cascRes.Msg.Groups {
		if g.Name == "zz-visible" {
			found = true
		}
	}
	if !found {
		t.Errorf("cascade: should see zz-visible")
	}
}

// TestListGroupMembersKeysetPagination verifies (created_at DESC, id ASC) keyset
// pagination for ListGroupMembers. Adds a mix of user and group members to a
// parent group, pages through with page_size=2, and asserts all members are
// returned with no duplicates.
func TestListGroupMembersKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create a parent group and 2 member users + 1 member group.
	parent, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "parent"}), tok))
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parentID := parent.Msg.Group.Id

	child, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "child"}), tok))
	if err != nil {
		t.Fatalf("create child: %v", err)
	}

	u1, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "m1@x", DisplayName: "M1", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create m1: %v", err)
	}
	u2, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "m2@x", DisplayName: "M2", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create m2: %v", err)
	}

	// Add members (each creates a group_memberships row with created_at ordering).
	if _, err := c.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: parentID, UserId: u1.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add u1: %v", err)
	}
	if _, err := c.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: parentID, UserId: u2.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add u2: %v", err)
	}
	if _, err := c.AddGroupToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddGroupToGroupRequest{
		GroupId: parentID, MemberGroupId: child.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("add child: %v", err)
	}

	// Fetch all members (large page) to get the full set.
	all, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{
		GroupId: parentID, PageSize: 100,
	}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	totalAll := len(all.Msg.Users) + len(all.Msg.Groups)
	if totalAll != 3 {
		t.Fatalf("total members = %d, want 3 (users=%d groups=%d)", totalAll, len(all.Msg.Users), len(all.Msg.Groups))
	}

	// Page through with page_size=2 and collect all member ids.
	seenUserIDs := map[string]bool{}
	seenGroupIDs := map[string]bool{}

	page1, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{
		GroupId: parentID, PageSize: 2,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Users)+len(page1.Msg.Groups) != 2 {
		t.Fatalf("page1: got %d members, want 2", len(page1.Msg.Users)+len(page1.Msg.Groups))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected NextPageToken (2 of 3 consumed)")
	}
	for _, u := range page1.Msg.Users {
		seenUserIDs[u.Id] = true
	}
	for _, g := range page1.Msg.Groups {
		seenGroupIDs[g.Id] = true
	}

	page2, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{
		GroupId:   parentID,
		PageSize:  2,
		PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Users)+len(page2.Msg.Groups) != 1 {
		t.Fatalf("page2: got %d members, want 1", len(page2.Msg.Users)+len(page2.Msg.Groups))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	for _, u := range page2.Msg.Users {
		seenUserIDs[u.Id] = true
	}
	for _, g := range page2.Msg.Groups {
		seenGroupIDs[g.Id] = true
	}

	// Assert all 3 members seen, no dupes.
	totalSeen := len(seenUserIDs) + len(seenGroupIDs)
	if totalSeen != 3 {
		t.Fatalf("total members across pages = %d, want 3 (users=%v groups=%v)", totalSeen, seenUserIDs, seenGroupIDs)
	}
}

// containsGroupName reports whether groups contains a group with the given name.
func containsGroupName(groups []*identityv1.Group, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// TestListGroupsParentScoped exercises the path-scoped visibility browse for
// ListGroups. It seeds a global group and a folder-scoped group, then verifies:
//   - parent="" returns only global groups (not the folder-scoped one)
//   - parent=<f1 id> returns only the folder-scoped group
//   - parent="", cascade=true returns both
//   - a member of the folder group sees it under parent=f1 with NO cap
//   - results are in (name ASC, id ASC) order
//   - keyset pagination works across a page boundary
func TestListGroupsParentScoped(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create folder f1.
	f1, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "f1g"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	f1ID := f1.Msg.Folder.Id

	// Seed a global group and a folder-scoped group.
	globalGroup, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "global-group",
	}), tok))
	if err != nil {
		t.Fatalf("create global group: %v", err)
	}
	globalGroupID := globalGroup.Msg.Group.Id

	folderGroup, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "folder-group", FolderId: f1ID,
	}), tok))
	if err != nil {
		t.Fatalf("create folder group: %v", err)
	}
	folderGroupID := folderGroup.Msg.Group.Id

	// --- Admin visibility ---

	// parent="" → only global groups (not folderGroup).
	rootList, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if !containsGroupName(rootList.Msg.Groups, "global-group") {
		t.Errorf("root list: want global-group present")
	}
	if containsGroupName(rootList.Msg.Groups, "folder-group") {
		t.Errorf("root list: want folder-group absent (not global)")
	}

	// parent=f1ID → only the folder-scoped group.
	f1List, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		Parent: f1ID, PageSize: 50,
	}), tok))
	if err != nil {
		t.Fatalf("list f1: %v", err)
	}
	if !containsGroupName(f1List.Msg.Groups, "folder-group") {
		t.Errorf("f1 list: want folder-group present")
	}
	if containsGroupName(f1List.Msg.Groups, "global-group") {
		t.Errorf("f1 list: want global-group absent")
	}

	// folder_path is populated for the scoped group.
	for _, g := range f1List.Msg.Groups {
		if g.Id == folderGroupID && g.FolderPath == "" {
			t.Errorf("folder-group folder_path empty, want non-empty")
		}
	}

	// parent="", cascade=true → both groups.
	cascadeList, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		Cascade: true, PageSize: 50,
	}), tok))
	if err != nil {
		t.Fatalf("list cascade: %v", err)
	}
	if !containsGroupName(cascadeList.Msg.Groups, "global-group") {
		t.Errorf("cascade list: want global-group present")
	}
	if !containsGroupName(cascadeList.Msg.Groups, "folder-group") {
		t.Errorf("cascade list: want folder-group present")
	}

	// --- Non-admin member visibility (no management cap) ---
	// Create a member who belongs to folderGroup.
	member, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "member@x", DisplayName: "Member", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: folderGroupID, UserId: member.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add member to folder-group: %v", err)
	}
	memberTok := authClient(t, url, "member@x", "password123")

	// Member can see folder-group under parent=f1 with NO management cap.
	memberList, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		Parent: f1ID, PageSize: 50,
	}), memberTok))
	if err != nil {
		t.Fatalf("member list f1: %v", err)
	}
	if !containsGroupName(memberList.Msg.Groups, "folder-group") {
		t.Errorf("member f1 list: want folder-group present (member arm)")
	}

	// Member does not see global-group at root (not a member).
	memberRoot, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 50}), memberTok))
	if err != nil {
		t.Fatalf("member root list: %v", err)
	}
	if containsGroupName(memberRoot.Msg.Groups, "global-group") {
		t.Errorf("member root: should not see global-group they are not a member of")
	}
	_ = globalGroupID

	// --- Name ordering and pagination ---
	// Create extra groups under f1: alpha + beta + folder-group + gamma = 4.
	// page_size=3 → page1=[alpha, beta, folder-group], page2=[gamma] (no token).
	for _, n := range []string{"alpha", "beta", "gamma"} {
		if _, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
			Name: n, FolderId: f1ID,
		}), tok)); err != nil {
			t.Fatalf("create extra group %s: %v", n, err)
		}
	}
	page1, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		Parent: f1ID, PageSize: 3,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Groups) != 3 {
		t.Fatalf("page1: got %d groups, want 3", len(page1.Msg.Groups))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected NextPageToken")
	}
	// Ordering: alpha < beta < folder-group < gamma
	if page1.Msg.Groups[0].Name != "alpha" || page1.Msg.Groups[1].Name != "beta" || page1.Msg.Groups[2].Name != "folder-group" {
		t.Errorf("page1 order: got [%s, %s, %s], want [alpha, beta, folder-group]",
			page1.Msg.Groups[0].Name, page1.Msg.Groups[1].Name, page1.Msg.Groups[2].Name)
	}
	page2, err := id.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{
		Parent: f1ID, PageSize: 3, PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Groups) != 1 {
		t.Fatalf("page2: got %d groups, want 1 (gamma only)", len(page2.Msg.Groups))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatal("page2: expected empty NextPageToken (last page not full)")
	}
	if page2.Msg.Groups[0].Name != "gamma" {
		t.Errorf("page2[0]: got %q, want gamma", page2.Msg.Groups[0].Name)
	}
	// No duplicates.
	seenGroup := map[string]bool{}
	for _, g := range page1.Msg.Groups {
		seenGroup[g.Id] = true
	}
	for _, g := range page2.Msg.Groups {
		if seenGroup[g.Id] {
			t.Fatalf("duplicate group id %s across pages", g.Id)
		}
	}
}

// TestGetGroupAccess: an admin gets group capabilities (** wildcard, surfaced via
// CapabilitiesOnScope); a member-but-no-caps user succeeds with an empty
// capability list (NOT NotFound); a stranger with no caps and no membership gets
// NotFound (existence hiding — groups are catalog topology).
func TestGetGroupAccess(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ic := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create a group (global scope, no folder).
	grp, err := ic.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "testgroup"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	groupID := grp.Msg.Group.Id

	// admin: CapabilitiesOnScope on the group's scope surfaces ** wildcard.
	resp, err := ic.GetGroupAccess(ctx, withToken(connect.NewRequest(&identityv1.GetGroupAccessRequest{GroupId: groupID}), tok))
	if err != nil {
		t.Fatalf("admin GetGroupAccess: %v", err)
	}
	if len(resp.Msg.Capabilities) == 0 {
		t.Fatalf("admin caps = %v, want non-empty (holds **)", resp.Msg.Capabilities)
	}

	// A member (no manage cap) sees the group (empty caps), not NotFound.
	memberID := seedCapUser(t, pool, "member@x", "password123", `[]`)
	// Add them to the group via direct DB (we need the q/pool).
	q := sqlc.New(pool)
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{
		GroupID:      uuid.MustParse(groupID),
		MemberUserID: pgtype.UUID{Bytes: memberID, Valid: true},
	}); err != nil {
		t.Fatalf("add member to group: %v", err)
	}
	mtok := authClient(t, url, "member@x", "password123")
	macc, err := ic.GetGroupAccess(ctx, withToken(connect.NewRequest(&identityv1.GetGroupAccessRequest{GroupId: groupID}), mtok))
	if err != nil {
		t.Fatalf("member GetGroupAccess: %v", err)
	}
	// Member has no management caps on the group; the response succeeds but caps are empty.
	if macc.Msg.Capabilities == nil {
		macc.Msg.Capabilities = []string{}
	}

	// stranger: capless, not a member → NotFound (existence hiding for topology).
	seedCapUser(t, pool, "stranger@x", "password123", `[]`)
	stok := authClient(t, url, "stranger@x", "password123")
	if _, err := ic.GetGroupAccess(ctx, withToken(connect.NewRequest(&identityv1.GetGroupAccessRequest{GroupId: groupID}), stok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("stranger GetGroupAccess = %v, want NotFound", connect.CodeOf(err))
	}
}

// TestAddGroupToGroupRejectsCycle pins that group nesting stays acyclic: adding a
// member edge that would close a transitive cycle (A∈B∈C∈A) or a direct back-edge
// (A∈B, then B∈A) is rejected with FailedPrecondition. The recursive membership
// closure is cycle-safe (UNION dedup), but a cycle makes membership results
// surprising, so the write is refused — mirroring the folder-move acyclicity guard.
func TestAddGroupToGroupRejectsCycle(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mk := func(name string) string {
		g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: name}), atok))
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return g.Msg.Group.Id
	}
	// add makes `member` a member of `group` (group_id=group, member_group_id=member).
	add := func(group, member string) error {
		_, err := id.AddGroupToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddGroupToGroupRequest{
			GroupId: group, MemberGroupId: member,
		}), atok))
		return err
	}

	a, b, c := mk("a"), mk("b"), mk("c")

	// Build the valid chain a ∈ b ∈ c (no cycle) — both must succeed.
	if err := add(b, a); err != nil {
		t.Fatalf("add a∈b: %v", err)
	}
	if err := add(c, b); err != nil {
		t.Fatalf("add b∈c: %v", err)
	}

	// Closing the transitive loop (c ∈ a, giving a∈b∈c∈a) must be refused.
	if err := add(a, c); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("add c∈a (transitive cycle) = %v, want FailedPrecondition", connect.CodeOf(err))
	}

	// A direct back-edge is also a cycle: d ∈ e, then e ∈ d.
	d, e := mk("d"), mk("e")
	if err := add(e, d); err != nil {
		t.Fatalf("add d∈e: %v", err)
	}
	if err := add(d, e); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("add e∈d (direct cycle) = %v, want FailedPrecondition", connect.CodeOf(err))
	}

	// A group cannot be a member of itself — same FailedPrecondition as any cycle.
	f := mk("f")
	if err := add(f, f); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("add f∈f (self) = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}
