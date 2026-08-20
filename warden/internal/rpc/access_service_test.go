package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

func TestAccessRoleCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err := c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "nope", Capabilities: []string{"db:read"}}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateRole = %v, want PermissionDenied", connect.CodeOf(err))
	}

	r, err := c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "readonly", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if r.Msg.Role.Name != "readonly" || len(r.Msg.Role.Capabilities) != 1 {
		t.Fatalf("role: %+v", r.Msg.Role)
	}
	roles, err := c.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles.Msg.Roles) < 1 {
		t.Fatalf("want >=1 role")
	}
	// GetRole round-trips.
	got, err := c.GetRole(ctx, withToken(connect.NewRequest(&accessv1.GetRoleRequest{Id: r.Msg.Role.Id}), tok))
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if got.Msg.Role.Id != r.Msg.Role.Id || got.Msg.Role.Name != "readonly" {
		t.Fatalf("get role mismatch: %+v", got.Msg.Role)
	}
}

// TestCreateRoleCapabilityValidation pins the proto-level capability grammar:
// CreateRole must reject unscoped/junk capabilities with InvalidArgument and
// accept valid scoped concrete and glob forms.
func TestCreateRoleCapabilityValidation(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Invalid: unscoped single segment.
	_, err := c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "bad-unscoped", Capabilities: []string{"admin"},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CreateRole(admin) = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Invalid: junk with spaces/uppercase.
	_, err = c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "bad-junk", Capabilities: []string{"DROP TABLE"},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CreateRole(DROP TABLE) = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Invalid: non-final '**'.
	_, err = c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "bad-dstar", Capabilities: []string{"k8s:**:x"},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("CreateRole(k8s:**:x) = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Valid: scoped concrete + globs.
	r, err := c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "good", Capabilities: []string{"ssh:connect", "k8s:*", "db:**", "k8s:impersonate:cluster-admin"},
	}), tok))
	if err != nil {
		t.Fatalf("CreateRole(valid scoped/glob) = %v, want ok", err)
	}
	if len(r.Msg.Role.Capabilities) != 4 {
		t.Fatalf("capabilities = %v, want 4", r.Msg.Role.Capabilities)
	}
}

func TestRoleGrantCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustRole := func(name string) string {
		r, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: name, Capabilities: []string{"db:read"}}), tok))
		if err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		return r.Msg.Role.Id
	}
	editor := mustRole("editor")
	owner := mustRole("owner")

	// editor ⊇ owner same_object
	g1, err := acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if err != nil {
		t.Fatalf("add same_object grant: %v", err)
	}
	if g1.Msg.Grant.Id == "" || g1.Msg.Grant.Via != "same_object" {
		t.Fatalf("unexpected grant %+v", g1.Msg.Grant)
	}
	// editor ⊇ editor parent (folder-cascade self-rule)
	if _, err := acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: editor, Via: "parent",
	}), tok)); err != nil {
		t.Fatalf("add parent grant: %v", err)
	}

	// list returns both
	lst, err := acc.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{RoleId: editor}), tok))
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(lst.Msg.Grants) != 2 {
		t.Fatalf("list grants = %d, want 2", len(lst.Msg.Grants))
	}

	// same_object self-reference → InvalidArgument
	_, err = acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: owner, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("same-object self = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// duplicate → AlreadyExists
	_, err = acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate = %v, want AlreadyExists", connect.CodeOf(err))
	}

	// remove then list shows it gone
	if _, err := acc.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.RemoveRoleGrantRequest{Id: g1.Msg.Grant.Id}), tok)); err != nil {
		t.Fatalf("remove grant: %v", err)
	}
	lst2, err := acc.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{RoleId: editor}), tok))
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(lst2.Msg.Grants) != 1 {
		t.Fatalf("list after remove = %d, want 1", len(lst2.Msg.Grants))
	}

	// non-admin rejected on all admin ops
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{RoleId: editor, SourceRoleId: owner, Via: "same_object"}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin add = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err = acc.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.RemoveRoleGrantRequest{Id: g1.Msg.Grant.Id}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin remove = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err = acc.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{RoleId: editor}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin list = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestRoleBindingCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "op", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatal(err)
	}

	// valid: group -> role STANDING on folder
	rb, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if rb.Msg.Id == "" {
		t.Fatal("empty binding id")
	}

	// invalid: two scopes set
	_, err = acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, ScopeAssetId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-scope binding = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// invalid: no subject
	_, err = acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no-subject binding = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// delete works
	if _, err := acc.DeleteRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: rb.Msg.Id}), tok)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f.Msg.Folder.Id, SubjectGroupId: g.Msg.Group.Id,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin binding = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestListRoleBindings exercises the optional filters: by role, and by scope.
func TestListRoleBindings(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	fA, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	fB, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "staging"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	roleX, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "rx", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	roleY, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "ry", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatal(err)
	}

	// roleX@fA, roleX@fB, roleY@fA
	mkBinding := func(roleID, folderID string) {
		if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
			RoleId: roleID, ScopeFolderId: folderID, SubjectGroupId: g.Msg.Group.Id,
		}), tok)); err != nil {
			t.Fatalf("binding %s@%s: %v", roleID, folderID, err)
		}
	}
	mkBinding(roleX.Msg.Role.Id, fA.Msg.Folder.Id)
	mkBinding(roleX.Msg.Role.Id, fB.Msg.Folder.Id)
	mkBinding(roleY.Msg.Role.Id, fA.Msg.Folder.Id)

	// no filter: all three
	all, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Msg.Bindings) != 3 {
		t.Fatalf("list all = %d, want 3", len(all.Msg.Bindings))
	}

	// filter by role: roleX → 2
	byRole, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{RoleId: roleX.Msg.Role.Id}), tok))
	if err != nil {
		t.Fatalf("list by role: %v", err)
	}
	if len(byRole.Msg.Bindings) != 2 {
		t.Fatalf("list by role = %d, want 2", len(byRole.Msg.Bindings))
	}
	for _, b := range byRole.Msg.Bindings {
		if b.RoleId != roleX.Msg.Role.Id {
			t.Fatalf("filtered binding has role %s, want %s", b.RoleId, roleX.Msg.Role.Id)
		}
	}

	// filter by scope folder: fA → 2 (roleX@fA + roleY@fA)
	byScope, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{ScopeFolderId: fA.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list by scope: %v", err)
	}
	if len(byScope.Msg.Bindings) != 2 {
		t.Fatalf("list by scope = %d, want 2", len(byScope.Msg.Bindings))
	}
	for _, b := range byScope.Msg.Bindings {
		if b.ScopeFolderId != fA.Msg.Folder.Id {
			t.Fatalf("filtered binding has scope %s, want %s", b.ScopeFolderId, fA.Msg.Folder.Id)
		}
	}

	// combined role+scope filter: roleX@fA → 1
	byBoth, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{
		RoleId: roleX.Msg.Role.Id, ScopeFolderId: fA.Msg.Folder.Id,
	}), tok))
	if err != nil {
		t.Fatalf("list by both: %v", err)
	}
	if len(byBoth.Msg.Bindings) != 1 {
		t.Fatalf("list by both = %d, want 1", len(byBoth.Msg.Bindings))
	}

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin list bindings = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestExplainRole(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustF := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.Folder.Id
	}
	// folder prod ⊃ db; asset pg in db.
	prod := mustF("prod", "")
	dbf := mustF("db", prod)
	pg, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: dbf, Name: "pg"}), tok))
	if err != nil {
		t.Fatalf("asset pg: %v", err)
	}
	pgID := pg.Msg.Asset.Id

	owner, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "owner", Capabilities: []string{"db:**"}}), tok))
	if err != nil {
		t.Fatalf("role owner: %v", err)
	}
	ownerID := owner.Msg.Role.Id
	// owner ⊇ owner parent — cascades down the folder chain.
	if _, err := acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: ownerID, SourceRoleId: ownerID, Via: "parent",
	}), tok)); err != nil {
		t.Fatalf("owner parent grant: %v", err)
	}

	// alice (non-admin) in group sre; sre standing owner@prod.
	alice, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "alice@x", DisplayName: "Alice", Password: "password123"}), tok))
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	aliceID := alice.Msg.User.Id
	sre, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{GroupId: sre.Msg.Group.Id, UserId: aliceID}), tok)); err != nil {
		t.Fatalf("add to group: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: ownerID, ScopeFolderId: prod, SubjectGroupId: sre.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("binding: %v", err)
	}

	// admin explains alice: holds via prod folder binding.
	exp, err := acc.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !exp.Msg.Holds {
		t.Fatal("expected holds=true")
	}
	if len(exp.Msg.Paths) == 0 {
		t.Fatal("expected at least one path")
	}
	p := exp.Msg.Paths[0]
	if len(p.Steps) == 0 {
		t.Fatal("expected non-empty steps")
	}
	if p.Subject != "group:"+sre.Msg.Group.Id {
		t.Fatalf("subject = %q, want group:%s", p.Subject, sre.Msg.Group.Id)
	}
	// path ends at the prod folder goal that the binding satisfies.
	last := p.Steps[len(p.Steps)-1]
	if last.ObjectKind != "folder" || last.ObjectId != prod || last.RoleId != ownerID {
		t.Fatalf("last step = %+v, want owner@folder:prod", last)
	}
	if p.BindingId == "" {
		t.Fatal("expected binding id")
	}

	// multi-path: add a SECOND, distinct derivation — a direct standing binding of
	// owner on the asset itself (subject = alice). She now holds owner@pg via both
	// the prod folder-cascade path and this direct-on-asset path.
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: ownerID, ScopeAssetId: pgID, SubjectUserId: aliceID,
	}), tok)); err != nil {
		t.Fatalf("direct asset binding: %v", err)
	}
	multiExp, err := acc.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain multi: %v", err)
	}
	if !multiExp.Msg.Holds {
		t.Fatal("expected holds=true with two derivations")
	}
	if len(multiExp.Msg.Paths) < 2 {
		t.Fatalf("expected >= 2 paths via two derivations, got %d", len(multiExp.Msg.Paths))
	}

	// negative: bob has no path.
	bob, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "bob@x", DisplayName: "Bob", Password: "password123"}), tok))
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	nexp, err := acc.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{
		UserId: bob.Msg.User.Id, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain bob: %v", err)
	}
	if nexp.Msg.Holds || len(nexp.Msg.Paths) != 0 {
		t.Fatalf("bob holds=%v paths=%d, want false/0", nexp.Msg.Holds, len(nexp.Msg.Paths))
	}

	// non-admin explaining ANOTHER user → PermissionDenied.
	atok := authClient(t, url, "alice@x", "password123")
	_, err = acc.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{
		UserId: bob.Msg.User.Id, RoleId: ownerID, AssetId: pgID,
	}), atok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("alice explains bob = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// non-admin explaining THEMSELVES → allowed.
	selfExp, err := acc.ExplainRole(ctx, withToken(connect.NewRequest(&accessv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), atok))
	if err != nil {
		t.Fatalf("alice explains self: %v", err)
	}
	if !selfExp.Msg.Holds {
		t.Fatal("alice self-explain: expected holds=true")
	}
}

func TestRequestPolicyCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)

	// Create a role via access
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "db-admin", Capabilities: []string{"db:read", "db:write"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	// Create a folder + asset
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

	// Create a group to use as approver subject
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "dba-approvers"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// non-admin CreateRequestPolicy → PermissionDenied
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId: roleID, RequiredApprovals: 1,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateRequestPolicy = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// CreateRequestPolicy with BOTH scope_folder_id and scope_asset_id → InvalidArgument
	_, err = acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		ScopeFolderId:     folder.Msg.Folder.Id,
		ScopeAssetId:      assetID,
		RequiredApprovals: 2,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-scope CreateRequestPolicy = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Create a role-default policy (both scope fields empty), required=2
	policy, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		RequiredApprovals: 2,
	}), tok))
	if err != nil {
		t.Fatalf("create request policy: %v", err)
	}
	if policy.Msg.Policy.Id == "" {
		t.Fatal("expected non-empty policy id")
	}
	if policy.Msg.Policy.RequiredApprovals != 2 {
		t.Fatalf("required_approvals = %d, want 2", policy.Msg.Policy.RequiredApprovals)
	}
	policyID := policy.Msg.Policy.Id

	// Add a group approver subject
	approver, err := acc.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
		PolicyId:       policyID,
		Kind:           "approver",
		SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("add policy subject: %v", err)
	}
	if approver.Msg.Id == "" {
		t.Fatal("expected non-empty subject id")
	}

	// AddPolicySubject with no subject → InvalidArgument
	_, err = acc.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
		PolicyId: policyID, Kind: "approver",
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no-subject AddPolicySubject = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// AddPolicySubject with both subjects → InvalidArgument
	_, err = acc.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
		PolicyId:       policyID,
		Kind:           "approver",
		SubjectUserId:  "00000000-0000-0000-0000-000000000001",
		SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-subject AddPolicySubject = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// ListRequestPolicies: should have >= 1
	policies, err := acc.ListRequestPolicies(ctx, withToken(connect.NewRequest(&accessv1.ListRequestPoliciesRequest{
		RoleId: roleID,
	}), tok))
	if err != nil {
		t.Fatalf("list request policies: %v", err)
	}
	if len(policies.Msg.Policies) < 1 {
		t.Fatalf("want >=1 policy, got %d", len(policies.Msg.Policies))
	}

	// RemovePolicySubject
	if _, err := acc.RemovePolicySubject(ctx, withToken(connect.NewRequest(&accessv1.RemovePolicySubjectRequest{
		Id: approver.Msg.Id,
	}), tok)); err != nil {
		t.Fatalf("remove policy subject: %v", err)
	}

	// DeleteRequestPolicy
	if _, err := acc.DeleteRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.DeleteRequestPolicyRequest{
		Id: policyID,
	}), tok)); err != nil {
		t.Fatalf("delete request policy: %v", err)
	}
}

// TestCreateRequestPolicyName verifies the optional policy name field:
// - a named asset-scoped policy round-trips GetName()
// - a second policy with the same name on the same asset returns AlreadyExists
// - existing nameless policies still create fine (name is optional)
func TestCreateRequestPolicyName(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "deploy-role", Capabilities: []string{"ssh:connect"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	asset, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folder.Msg.Folder.Id, Name: "web-server",
	}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assetID := asset.Msg.Asset.Id

	// Named asset-scoped policy: name must round-trip.
	p1, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		ScopeAssetId:      assetID,
		RequiredApprovals: 1,
		Name:              "approve-deploy",
	}), tok))
	if err != nil {
		t.Fatalf("create named policy: %v", err)
	}
	if p1.Msg.Policy.GetName() != "approve-deploy" {
		t.Fatalf("name = %q, want %q", p1.Msg.Policy.GetName(), "approve-deploy")
	}

	// Second policy with the same name on the same asset → AlreadyExists.
	// Use a DIFFERENT role so the per-role uq_rule_role_asset index doesn't
	// fire first: this must fail specifically on uq_policy_name_asset, which
	// is the name-uniqueness constraint under test.
	dupRole, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "deploy-role-dup", Capabilities: []string{"ssh:connect"},
	}), tok))
	if err != nil {
		t.Fatalf("create dup role: %v", err)
	}
	_, err = acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            dupRole.Msg.Role.Id,
		ScopeAssetId:      assetID,
		RequiredApprovals: 2,
		Name:              "approve-deploy",
	}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate name = %v (code %v), want AlreadyExists", err, connect.CodeOf(err))
	}

	// Nameless policy on a different role+asset still creates fine (name is optional).
	role2, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "ops-role", Capabilities: []string{"ssh:connect"},
	}), tok))
	if err != nil {
		t.Fatalf("create role2: %v", err)
	}
	asset2, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folder.Msg.Folder.Id, Name: "db-server",
	}), tok))
	if err != nil {
		t.Fatalf("create asset2: %v", err)
	}
	p3, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            role2.Msg.Role.Id,
		ScopeAssetId:      asset2.Msg.Asset.Id,
		RequiredApprovals: 1,
	}), tok))
	if err != nil {
		t.Fatalf("create nameless policy: %v", err)
	}
	if p3.Msg.Policy.GetName() != "" {
		t.Fatalf("nameless policy name = %q, want empty", p3.Msg.Policy.GetName())
	}
}

// TestRequestPolicySelfServiceAndMaxDuration covers M3c policy-config surface
// additions: required_approvals=0 (self-service) is now accepted, and
// max_duration_seconds round-trips through Create → ListRequestPolicies.
func TestRequestPolicySelfServiceAndMaxDuration(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "self-service-role", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	// required_approvals=0 (self-service) now SUCCEEDS; max_duration_seconds set.
	policy, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:             roleID,
		RequiredApprovals:  0,
		MaxDurationSeconds: 3600,
	}), tok))
	if err != nil {
		t.Fatalf("create self-service policy: %v", err)
	}
	if policy.Msg.Policy.RequiredApprovals != 0 {
		t.Fatalf("required_approvals = %d, want 0", policy.Msg.Policy.RequiredApprovals)
	}
	if policy.Msg.Policy.MaxDurationSeconds != 3600 {
		t.Fatalf("max_duration_seconds = %d, want 3600 (Create response)", policy.Msg.Policy.MaxDurationSeconds)
	}

	// max_duration_seconds round-trips through a subsequent read.
	policies, err := acc.ListRequestPolicies(ctx, withToken(connect.NewRequest(&accessv1.ListRequestPoliciesRequest{
		RoleId: roleID,
	}), tok))
	if err != nil {
		t.Fatalf("list request policies: %v", err)
	}
	var found *accessv1.RequestPolicy
	for _, p := range policies.Msg.Policies {
		if p.Id == policy.Msg.Policy.Id {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatal("created policy not found in ListRequestPolicies")
	}
	if found.MaxDurationSeconds != 3600 {
		t.Fatalf("max_duration_seconds = %d, want 3600 (list read)", found.MaxDurationSeconds)
	}

	// Update to clear the cap (0 → NULL) and keep self-service.
	upd, err := acc.UpdateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.UpdateRequestPolicyRequest{
		Id:                 policy.Msg.Policy.Id,
		RequiredApprovals:  0,
		MaxDurationSeconds: 0,
	}), tok))
	if err != nil {
		t.Fatalf("update request policy: %v", err)
	}
	if upd.Msg.Policy.MaxDurationSeconds != 0 {
		t.Fatalf("updated max_duration_seconds = %d, want 0 (NULL)", upd.Msg.Policy.MaxDurationSeconds)
	}
}

// TestResolvePolicy verifies AccessService.ResolvePolicy: admin resolves
// (name, asset_id) → policy_id; wrong name → NotFound; non-admin → PermissionDenied.
func TestResolvePolicy(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "deploy-role", Capabilities: []string{"ssh:connect"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	asset, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folder.Msg.Folder.Id, Name: "web-server",
	}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assetID := asset.Msg.Asset.Id

	// Create a named asset-scoped policy.
	p1, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		ScopeAssetId:      assetID,
		RequiredApprovals: 1,
		Name:              "approve-deploy",
	}), tok))
	if err != nil {
		t.Fatalf("create named policy: %v", err)
	}
	polID := p1.Msg.Policy.Id

	ac := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	// admin resolves by (name, asset_id)
	got, err := ac.ResolvePolicy(ctx, withToken(connect.NewRequest(&accessv1.ResolvePolicyRequest{Name: "approve-deploy", AssetId: assetID}), tok))
	if err != nil || got.Msg.PolicyId != polID {
		var gotID string
		if got != nil {
			gotID = got.Msg.PolicyId
		}
		t.Fatalf("resolve = %v / %q, want %s", err, gotID, polID)
	}
	// wrong name → NotFound
	if _, err := ac.ResolvePolicy(ctx, withToken(connect.NewRequest(&accessv1.ResolvePolicyRequest{Name: "nope", AssetId: assetID}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("wrong name = %v, want NotFound", connect.CodeOf(err))
	}
	// non-admin → PermissionDenied
	seedUser(t, pool, "u2@x", "password123", false)
	utok := authClient(t, url, "u2@x", "password123")
	if _, err := ac.ResolvePolicy(ctx, withToken(connect.NewRequest(&accessv1.ResolvePolicyRequest{Name: "approve-deploy", AssetId: assetID}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestRequestPolicyRequesterSide is the additive requester-side coverage:
// CreateRequestPolicy with requester_role_id set + a kind='requester' subject
// that round-trips via ListPolicySubjects.
func TestRequestPolicyRequesterSide(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "target", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	requesterRole, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "requester-src", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create requester role: %v", err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "requesters"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// CreateRequestPolicy sets requester_role_id.
	policy, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            role.Msg.Role.Id,
		RequiredApprovals: 1,
		RequesterRoleId:   requesterRole.Msg.Role.Id,
	}), tok))
	if err != nil {
		t.Fatalf("create request policy: %v", err)
	}
	if policy.Msg.Policy.RequesterRoleId != requesterRole.Msg.Role.Id {
		t.Fatalf("requester_role_id = %q, want %q", policy.Msg.Policy.RequesterRoleId, requesterRole.Msg.Role.Id)
	}
	policyID := policy.Msg.Policy.Id

	// Add a kind='requester' group subject.
	sub, err := acc.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
		PolicyId:       policyID,
		Kind:           "requester",
		SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("add requester subject: %v", err)
	}

	// Round-trip via ListPolicySubjects.
	subs, err := acc.ListPolicySubjects(ctx, withToken(connect.NewRequest(&accessv1.ListPolicySubjectsRequest{
		PolicyId: policyID,
	}), tok))
	if err != nil {
		t.Fatalf("list policy subjects: %v", err)
	}
	var found *accessv1.PolicySubject
	for _, s := range subs.Msg.Subjects {
		if s.Id == sub.Msg.Id {
			found = s
		}
	}
	if found == nil {
		t.Fatalf("requester subject %s not found in %+v", sub.Msg.Id, subs.Msg.Subjects)
	}
	if found.Kind != "requester" {
		t.Fatalf("subject kind = %q, want requester", found.Kind)
	}
	if found.SubjectGroupId != g.Msg.Group.Id {
		t.Fatalf("subject group = %q, want %q", found.SubjectGroupId, g.Msg.Group.Id)
	}

	// UpdateRequestPolicy clears/keeps requester side and bumps approvals.
	upd, err := acc.UpdateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.UpdateRequestPolicyRequest{
		Id:                policyID,
		RequiredApprovals: 3,
		RequesterRoleId:   requesterRole.Msg.Role.Id,
	}), tok))
	if err != nil {
		t.Fatalf("update request policy: %v", err)
	}
	if upd.Msg.Policy.RequiredApprovals != 3 {
		t.Fatalf("updated required_approvals = %d, want 3", upd.Msg.Policy.RequiredApprovals)
	}
	if upd.Msg.Policy.RequesterRoleId != requesterRole.Msg.Role.Id {
		t.Fatalf("updated requester_role_id = %q, want %q", upd.Msg.Policy.RequesterRoleId, requesterRole.Msg.Role.Id)
	}
}

// TestRoleFolderScopeUniqueness pins the new roles model: names are unique among
// global roles and per-folder among scoped roles; the same name may exist in two
// different folders and as a global + scoped pair.
func TestRoleFolderScopeUniqueness(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mkFolder := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("create folder %s: %v", name, err)
		}
		return r.Msg.GetFolder().GetId()
	}
	mkRole := func(name, folderID string) error {
		_, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
			Name: name, FolderId: folderID, Capabilities: []string{"ssh:login:deploy"},
		}), tok))
		return err
	}

	prod := mkFolder("prod", "")
	dev := mkFolder("dev", "")

	if err := mkRole("engineer", ""); err != nil {
		t.Fatalf("global engineer: %v", err)
	}
	if err := mkRole("engineer", ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup global = %v, want AlreadyExists", connect.CodeOf(err))
	}
	if err := mkRole("engineer", prod); err != nil {
		t.Fatalf("engineer.prod: %v", err)
	}
	if err := mkRole("engineer", dev); err != nil {
		t.Fatalf("engineer.dev: %v", err)
	}
	if err := mkRole("engineer", prod); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup engineer.prod = %v, want AlreadyExists", connect.CodeOf(err))
	}
	if err := mkRole("Bad Name", ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad name = %v, want InvalidArgument", connect.CodeOf(err))
	}
}
