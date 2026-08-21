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

	// Valid: a bare '**' (match-everything) — the admin capability.
	rr, err := c.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "superadmin", Capabilities: []string{"**"},
	}), tok))
	if err != nil {
		t.Fatalf("CreateRole(bare **) = %v, want ok", err)
	}
	if len(rr.Msg.Role.Capabilities) != 1 || rr.Msg.Role.Capabilities[0] != "**" {
		t.Fatalf("capabilities = %v, want [**]", rr.Msg.Role.Capabilities)
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

// TestCreateGlobalRoleBinding creates a role binding with NEITHER scope set
// (a global binding). The DB one_scope constraint was relaxed to permit this and
// CreateRoleBinding now rejects only both-scopes-set, so a scopeless binding on a
// global role succeeds.
func TestCreateGlobalRoleBinding(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "global-op", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "everyone"}), tok))
	if err != nil {
		t.Fatal(err)
	}

	// global binding: no scope_folder_id, no scope_asset_id
	rb, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("create global binding: %v", err)
	}
	if rb.Msg.Id == "" {
		t.Fatal("empty global binding id")
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

	// no filter: the three created here plus the admin's scopeless `**` bootstrap
	// binding (seedUser grants it so the capability-gated handlers admit the admin).
	all, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Msg.Bindings) != 4 {
		t.Fatalf("list all = %d, want 4", len(all.Msg.Bindings))
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

// TestListRoleBindingsKeysetPagination verifies time-ordered (created_at DESC, id)
// keyset pagination for ListRoleBindings. Seeds 3 bindings (plus the bootstrap admin
// binding), requests page 1 with PageSize=2, asserts it returns 2 items and a
// non-empty NextPageToken, then fetches page 2 and asserts it returns the remaining
// items and an empty NextPageToken.
func TestListRoleBindingsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create a role and a folder for the bindings.
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "pg-role", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "pgfolder"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}

	// Create three groups, one binding each, so we have 3 additional rows in
	// addition to the admin bootstrap binding (4 total).
	var groupBindingIDs []string // in creation order (oldest first)
	mkBinding := func(groupName string) {
		g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: groupName}), tok))
		if err != nil {
			t.Fatalf("create group %s: %v", groupName, err)
		}
		b, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
			RoleId:         role.Msg.Role.Id,
			ScopeFolderId:  folder.Msg.Folder.Id,
			SubjectGroupId: g.Msg.Group.Id,
		}), tok))
		if err != nil {
			t.Fatalf("create binding for %s: %v", groupName, err)
		}
		groupBindingIDs = append(groupBindingIDs, b.Msg.Id)
	}
	mkBinding("grp-a")
	mkBinding("grp-b")
	mkBinding("grp-c")

	// Page 1: 3 items + non-empty token (4 total records, page_size=3).
	page1, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{
		PageSize: 3,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Bindings) != 3 {
		t.Fatalf("page1: got %d bindings, want 3", len(page1.Msg.Bindings))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}

	// Page 2: 1 remaining item + empty token (no further pages).
	page2, err := acc.ListRoleBindings(ctx, withToken(connect.NewRequest(&accessv1.ListRoleBindingsRequest{
		PageSize:  3,
		PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Bindings) == 0 {
		t.Fatal("page2: got 0 bindings, want >= 1")
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}

	// Total across both pages must equal 4 (3 created + 1 bootstrap admin binding).
	total := len(page1.Msg.Bindings) + len(page2.Msg.Bindings)
	if total != 4 {
		t.Fatalf("total bindings across pages = %d, want 4", total)
	}

	// No duplicates between pages.
	seen := map[string]bool{}
	for _, b := range page1.Msg.Bindings {
		seen[b.Id] = true
	}
	for _, b := range page2.Msg.Bindings {
		if seen[b.Id] {
			t.Fatalf("duplicate binding id %s across pages", b.Id)
		}
	}

	// Ordering: created_at DESC means the three most-recently-created (the group
	// bindings) fill page 1 in reverse creation order (grp-c, grp-b, grp-a), and
	// the oldest row (the bootstrap admin binding) lands last, on page 2. This
	// pins the keyset tiebreak direction — a wrong predicate would misorder or
	// leak the bootstrap binding onto page 1.
	wantP1 := []string{groupBindingIDs[2], groupBindingIDs[1], groupBindingIDs[0]}
	gotP1 := []string{page1.Msg.Bindings[0].Id, page1.Msg.Bindings[1].Id, page1.Msg.Bindings[2].Id}
	for i := range wantP1 {
		if gotP1[i] != wantP1[i] {
			t.Fatalf("page1 order = %v, want %v (newest-first)", gotP1, wantP1)
		}
	}
	if seen[page2.Msg.Bindings[0].Id] || contains(groupBindingIDs, page2.Msg.Bindings[0].Id) {
		t.Fatalf("page2 should hold the oldest (bootstrap) binding, got a group binding %s", page2.Msg.Bindings[0].Id)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
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

// TestResolveRole resolves a role by uuid, bare global name, and <role>.<folder-path>,
// and hides misses as NotFound; non-admins are denied.
func TestResolveRole(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	pr, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("folder: %v", err)
	}
	prod := pr.Msg.GetFolder().GetId()
	gr, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "engineer", Capabilities: []string{"ssh:login:deploy"}}), tok))
	if err != nil {
		t.Fatalf("global role: %v", err)
	}
	sr, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "engineer", FolderId: prod, Capabilities: []string{"ssh:login:deploy"}}), tok))
	if err != nil {
		t.Fatalf("scoped role: %v", err)
	}

	got, err := access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: sr.Msg.Role.Id}), tok))
	if err != nil || got.Msg.RoleId != sr.Msg.Role.Id {
		t.Fatalf("resolve by uuid: %v / %s", err, got.Msg.GetRoleId())
	}
	got, err = access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: "engineer"}), tok))
	if err != nil || got.Msg.RoleId != gr.Msg.Role.Id {
		t.Fatalf("resolve global: %v / %s", err, got.Msg.GetRoleId())
	}
	got, err = access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: "engineer.prod"}), tok))
	if err != nil || got.Msg.RoleId != sr.Msg.Role.Id {
		t.Fatalf("resolve scoped: %v / %s", err, got.Msg.GetRoleId())
	}
	if got.Msg.Path != "engineer.prod" {
		t.Fatalf("path = %q, want engineer.prod", got.Msg.Path)
	}
	if _, err := access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: "engineer.nope"}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("miss = %v, want NotFound", connect.CodeOf(err))
	}
	if _, err := access.ResolveRole(ctx, withToken(connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: "engineer"}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// folder_path is now populated on single-role GET reads
	grow, err := access.GetRole(ctx, withToken(connect.NewRequest(&accessv1.GetRoleRequest{Id: sr.Msg.Role.Id}), tok))
	if err != nil {
		t.Fatalf("get scoped role: %v", err)
	}
	if grow.Msg.Role.FolderPath != "prod" {
		t.Fatalf("GetRole folder_path = %q, want prod", grow.Msg.Role.FolderPath)
	}
}

// TestRoleContainment pins that a folder-scoped role is bindable/requestable only
// within its subtree, while a global role is unrestricted.
func TestRoleContainment(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mkFolder := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.GetFolder().GetId()
	}
	mkAsset := func(name, folder string) string {
		r, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: folder, Name: name}), tok))
		if err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return r.Msg.GetAsset().GetId()
	}
	subj, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "subject@x", DisplayName: "Subject", Password: "password123"}), tok))
	if err != nil {
		t.Fatalf("create subject: %v", err)
	}
	u := subj.Msg.User.Id

	prod := mkFolder("prod", "")
	dev := mkFolder("dev", "")
	inProd := mkAsset("box", prod)
	inDev := mkAsset("box", dev)

	scoped, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "engineer", FolderId: prod, Capabilities: []string{"ssh:login:deploy"}}), tok))
	if err != nil {
		t.Fatalf("scoped role: %v", err)
	}
	global, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "everywhere", Capabilities: []string{"ssh:login:deploy"}}), tok))
	if err != nil {
		t.Fatalf("global role: %v", err)
	}

	bind := func(roleID, assetID string) error {
		_, err := access.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
			RoleId: roleID, ScopeAssetId: assetID, SubjectUserId: u,
		}), tok))
		return err
	}
	if err := bind(scoped.Msg.Role.Id, inProd); err != nil {
		t.Fatalf("bind in-subtree: %v", err)
	}
	if err := bind(scoped.Msg.Role.Id, inDev); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("bind out-of-subtree = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if err := bind(global.Msg.Role.Id, inDev); err != nil {
		t.Fatalf("bind global: %v", err)
	}

	mkPolicy := func(name, roleID, assetID string) error {
		_, err := access.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
			Name: name, RoleId: roleID, ScopeAssetId: assetID, RequiredApprovals: 1,
		}), tok))
		return err
	}
	if err := mkPolicy("p1", scoped.Msg.Role.Id, inDev); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("policy out-of-subtree = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if err := mkPolicy("p2", scoped.Msg.Role.Id, inProd); err != nil {
		t.Fatalf("policy in-subtree: %v", err)
	}
	// scoped role in a scope-less policy → FailedPrecondition
	_, err = access.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		Name: "nofolder", RoleId: scoped.Msg.Role.Id, RequiredApprovals: 1,
	}), tok))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("scope-less scoped policy = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

// TestListRolesFolderPath verifies ListRoles populates folder_path for scoped roles.
func TestListRolesFolderPath(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	pr, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("folder: %v", err)
	}
	prod := pr.Msg.GetFolder().GetId()
	if _, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "engineer", FolderId: prod, Capabilities: []string{"ssh:login:deploy"}}), tok)); err != nil {
		t.Fatalf("scoped role: %v", err)
	}
	if _, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "everywhere", Capabilities: []string{"ssh:login:deploy"}}), tok)); err != nil {
		t.Fatalf("global role: %v", err)
	}
	resp, err := access.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var sawScoped, sawGlobal bool
	for _, r := range resp.Msg.Roles {
		switch r.Name {
		case "engineer":
			sawScoped = true
			if r.FolderPath != "prod" {
				t.Fatalf("engineer folder_path = %q, want prod", r.FolderPath)
			}
		case "everywhere":
			sawGlobal = true
			if r.FolderPath != "" {
				t.Fatalf("everywhere folder_path = %q, want empty", r.FolderPath)
			}
		}
	}
	if !sawScoped || !sawGlobal {
		t.Fatalf("missing roles in list (scoped=%v global=%v)", sawScoped, sawGlobal)
	}
}

// TestAccessCapabilityGatingAndSubset pins the capability-gated management surface
// and the no-escalation subset rule. dana is a non-admin holding
// [access:role:create, access:binding:create, ssh:login:*] at folder `team` (via a
// global role bound at that folder). She may create roles and bind subset roles
// within team, but may NOT bind roles carrying caps she lacks there (`**`,
// `identity:user:create`), and may NOT perform a global read (ListRoles).
func TestAccessCapabilityGatingAndSubset(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	seedUser(t, pool, "dana@x", "password123", false)
	danaTok := authClient(t, url, "dana@x", "password123")

	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	idc := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// admin (**) sets up: folder `team`, dana's management role (global) bound to
	// dana at folder `team`.
	fr, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "team"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	team := fr.Msg.Folder.Id

	mgmt, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name:         "team-mgr",
		Capabilities: []string{"access:role:create", "access:binding:create", "ssh:login:*"},
	}), tok))
	if err != nil {
		t.Fatalf("create mgmt role: %v", err)
	}

	danaRes, err := idc.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "dana@x"}), tok))
	if err != nil {
		t.Fatalf("resolve dana: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: mgmt.Msg.Role.Id, ScopeFolderId: team, SubjectUserId: danaRes.Msg.UserId,
	}), tok)); err != nil {
		t.Fatalf("bind dana: %v", err)
	}

	// dana CAN create a role scoped to `team`.
	deployRole, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "deployer", FolderId: team, Capabilities: []string{"ssh:login:deploy"},
	}), danaTok))
	if err != nil {
		t.Fatalf("dana CreateRole(team) = %v, want ok", err)
	}

	// dana CAN bind that subset role (ssh:login:deploy ⊆ ssh:login:*) at team.
	g, err := idc.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "team-grp"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: deployRole.Msg.Role.Id, ScopeFolderId: team, SubjectGroupId: g.Msg.Group.Id,
	}), danaTok)); err != nil {
		t.Fatalf("dana bind subset role = %v, want ok", err)
	}

	// dana CANNOT bind the global admin (**) role at team — she doesn't hold **.
	adminRole, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "superadmin", Capabilities: []string{"**"},
	}), tok))
	if err != nil {
		t.Fatalf("create admin role: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: adminRole.Msg.Role.Id, ScopeFolderId: team, SubjectGroupId: g.Msg.Group.Id,
	}), danaTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana bind ** at team = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// dana CAN create a role with identity:user:create (CreateRole is not
	// subset-limited) but CANNOT bind it at team (she lacks identity:*).
	idRole, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "user-admin", FolderId: team, Capabilities: []string{"identity:user:create"},
	}), danaTok))
	if err != nil {
		t.Fatalf("dana CreateRole(identity) = %v, want ok", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: idRole.Msg.Role.Id, ScopeFolderId: team, SubjectGroupId: g.Msg.Group.Id,
	}), danaTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana bind identity role at team = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// dana CANNOT ListRoles (a global read she lacks).
	if _, err := acc.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 50}), danaTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana ListRoles = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// admin (**) can do all of the above.
	if _, err := acc.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 50}), tok)); err != nil {
		t.Fatalf("admin ListRoles = %v, want ok", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: adminRole.Msg.Role.Id, ScopeFolderId: team, SubjectGroupId: g.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("admin bind ** at team = %v, want ok", err)
	}
}

// TestAddRoleGrantNoEscalation locks the DIRECTION of the AddRoleGrant subset
// guard so nobody "fixes" it backwards. AddRoleGrant(role_id=R, source_role_id=S)
// creates the rule "holding S CONFERS R" — the capability GAINED by the operation
// is R's (role_id's), NOT the source's. The guard therefore checks role_id's caps
// against what the actor holds. Checking source_role_id instead would OPEN a
// privilege-escalation hole. mallory holds a weak set (access:role:update +
// ssh:login:*) globally; she must be DENIED conferring a ** role (superpower) but
// ALLOWED conferring an ssh:login:deploy role (weak, ⊆ ssh:login:*).
func TestAddRoleGrantNoEscalation(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	seedUser(t, pool, "mallory@x", "password123", false)
	malloryTok := authClient(t, url, "mallory@x", "password123")

	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	idc := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// admin sets up mallory's management role bound GLOBALLY: she can call
	// AddRoleGrant (access:role:update) and confers ssh:login:* — but she does NOT
	// hold **.
	mgmt, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name:         "grant-mgr",
		Capabilities: []string{"access:role:update", "ssh:login:*"},
	}), tok))
	if err != nil {
		t.Fatalf("create mgmt role: %v", err)
	}
	malloryRes, err := idc.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "mallory@x"}), tok))
	if err != nil {
		t.Fatalf("resolve mallory: %v", err)
	}
	if _, err := acc.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: mgmt.Msg.Role.Id, SubjectUserId: malloryRes.Msg.UserId,
	}), tok)); err != nil {
		t.Fatalf("bind mallory globally: %v", err)
	}

	// admin creates global roles: a POWERFUL superpower (**), a WEAK weak
	// (ssh:login:deploy), and a src role used only as the grant source.
	superpower, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "superpower", Capabilities: []string{"**"},
	}), tok))
	if err != nil {
		t.Fatalf("create superpower: %v", err)
	}
	weak, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "weak", Capabilities: []string{"ssh:login:deploy"},
	}), tok))
	if err != nil {
		t.Fatalf("create weak: %v", err)
	}
	src, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "src", Capabilities: []string{"ssh:login:deploy"},
	}), tok))
	if err != nil {
		t.Fatalf("create src: %v", err)
	}

	// DENIED: conferring superpower (role_id=superpower). mallory holds
	// access:role:update globally (so the requireCap gate passes) but the subset
	// guard checks the RECIPIENT superpower's ** — which she lacks — so the deny is
	// specifically the escalation guard: PermissionDenied.
	_, err = acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: superpower.Msg.Role.Id, SourceRoleId: src.Msg.Role.Id, Via: "same_object",
	}), malloryTok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("mallory confer superpower = %v, want PermissionDenied (escalation blocked)", connect.CodeOf(err))
	}

	// ALLOWED: conferring weak (role_id=weak, ssh:login:deploy ⊆ mallory's
	// ssh:login:*) — subset guard passes and the grant is created.
	if _, err := acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
		RoleId: weak.Msg.Role.Id, SourceRoleId: src.Msg.Role.Id, Via: "same_object",
	}), malloryTok)); err != nil {
		t.Fatalf("mallory confer weak = %v, want ok (subset allowed)", err)
	}
}

// TestListRolesKeysetByName verifies name-ordered (name ASC, id ASC) keyset
// pagination for ListRoles. Seeds 3 roles with names in deliberately reversed
// alphabetical order (creation order = zzz-c, zzz-b, zzz-a) that are guaranteed
// to sort AFTER any bootstrap roles (all starting with "zzz-"), and confirms that
// page 1 returns them in NAME order, not creation order, and that the token
// terminates correctly.
func TestListRolesKeysetByName(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create 3 roles in deliberately reversed alphabetical order (c first, a last)
	// using a "zzz-" prefix so they reliably sort AFTER any bootstrap roles.
	// This proves the list is ordered by name, not by creation/id order.
	for _, name := range []string{"zzz-c", "zzz-b", "zzz-a"} {
		if _, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
			Name: name, Capabilities: []string{"db:read"},
		}), tok)); err != nil {
			t.Fatalf("create role %s: %v", name, err)
		}
	}

	// Fetch all roles with a large page, then filter to our 3 seeded roles to
	// verify they appear in name-ascending order (zzz-a < zzz-b < zzz-c).
	all, err := acc.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{
		PageSize: 100,
	}), tok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	var seededNames []string
	for _, r := range all.Msg.Roles {
		if r.Name == "zzz-a" || r.Name == "zzz-b" || r.Name == "zzz-c" {
			seededNames = append(seededNames, r.Name)
		}
	}
	wantNames := []string{"zzz-a", "zzz-b", "zzz-c"}
	for i, w := range wantNames {
		if i >= len(seededNames) || seededNames[i] != w {
			t.Fatalf("seeded roles out of order: got %v, want %v", seededNames, wantNames)
		}
	}

	// Verify keyset pagination on just the 3 seeded roles by requesting with
	// page_size=2; they land at the tail of the name-ordered list.
	// Collect all pages and verify: (1) no duplicates, (2) the three names
	// appear in zzz-a < zzz-b < zzz-c order across pages.
	var allPages []*accessv1.Role
	token := ""
	for {
		resp, err := acc.ListRoles(ctx, withToken(connect.NewRequest(&accessv1.ListRolesRequest{
			PageSize: 2, PageToken: token,
		}), tok))
		if err != nil {
			t.Fatalf("list page (token=%q): %v", token, err)
		}
		allPages = append(allPages, resp.Msg.Roles...)
		token = resp.Msg.NextPageToken
		if token == "" {
			break
		}
	}

	// No duplicates in the multi-page traversal.
	seen := map[string]bool{}
	for _, r := range allPages {
		if seen[r.Id] {
			t.Fatalf("duplicate role id %s across pages", r.Id)
		}
		seen[r.Id] = true
	}

	// The 3 seeded roles appear exactly once and in ascending name order.
	var got []string
	for _, r := range allPages {
		if r.Name == "zzz-a" || r.Name == "zzz-b" || r.Name == "zzz-c" {
			got = append(got, r.Name)
		}
	}
	for i, w := range wantNames {
		if i >= len(got) || got[i] != w {
			t.Fatalf("paginated seeded roles: got %v, want %v", got, wantNames)
		}
	}
}

// TestListRoleGrantsKeysetPagination verifies time-ordered (created_at DESC, id ASC)
// keyset pagination for ListRoleGrants. Seeds 3 role→role grant edges, pages
// through with page_size=2, and asserts newest-first ordering + token termination.
func TestListRoleGrantsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create the target role and 3 source roles.
	target, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "target-role", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	targetID := target.Msg.Role.Id

	var grantIDs []string // in creation order (oldest first)
	for i, name := range []string{"src-a", "src-b", "src-c"} {
		src, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
			Name: name, Capabilities: []string{"db:read"},
		}), tok))
		if err != nil {
			t.Fatalf("create source role %s: %v", name, err)
		}
		via := "same_object"
		if i > 0 {
			via = "parent"
		}
		g, err := acc.AddRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.AddRoleGrantRequest{
			RoleId: targetID, SourceRoleId: src.Msg.Role.Id, Via: via,
		}), tok))
		if err != nil {
			t.Fatalf("add grant for %s: %v", name, err)
		}
		grantIDs = append(grantIDs, g.Msg.Grant.Id)
	}

	// Page 1: 2 of the 3 grants (newest first), must have a token.
	page1, err := acc.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{
		RoleId: targetID, PageSize: 2,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Grants) != 2 {
		t.Fatalf("page1: got %d grants, want 2", len(page1.Msg.Grants))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}

	// Ordering: created_at DESC means src-c (newest) is first, then src-b.
	wantP1 := []string{grantIDs[2], grantIDs[1]}
	for i, want := range wantP1 {
		if page1.Msg.Grants[i].Id != want {
			t.Fatalf("page1[%d] = %s, want %s (newest-first order)", i, page1.Msg.Grants[i].Id, want)
		}
	}

	// Page 2: remaining 1 grant (src-a, the oldest), no token.
	page2, err := acc.ListRoleGrants(ctx, withToken(connect.NewRequest(&accessv1.ListRoleGrantsRequest{
		RoleId: targetID, PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Grants) != 1 {
		t.Fatalf("page2: got %d grants, want 1", len(page2.Msg.Grants))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Grants[0].Id != grantIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest grant)", page2.Msg.Grants[0].Id, grantIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, g := range page1.Msg.Grants {
		seen[g.Id] = true
	}
	for _, g := range page2.Msg.Grants {
		if seen[g.Id] {
			t.Fatalf("duplicate grant id %s across pages", g.Id)
		}
	}
}

// TestListRequestPoliciesKeysetPagination verifies time-ordered (created_at DESC, id ASC)
// keyset pagination for ListRequestPolicies. Seeds 3 policies for the same role
// (one default + two asset-scoped), pages with page_size=2, and asserts newest-first
// ordering + token termination.
func TestListRequestPoliciesKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "pol-role", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "pol-folder"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	folderID := folder.Msg.Folder.Id

	// Create 3 assets for scoped policies; each asset = one policy.
	var policyIDs []string // in creation order (oldest first)
	for _, assetName := range []string{"asset-a", "asset-b", "asset-c"} {
		a, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
			Name: assetName, FolderId: folderID, Kind: "ssh",
		}), tok))
		if err != nil {
			t.Fatalf("create asset %s: %v", assetName, err)
		}
		p, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
			RoleId:            roleID,
			ScopeAssetId:      a.Msg.Asset.Id,
			RequiredApprovals: 1,
			Name:              "policy-for-" + assetName,
		}), tok))
		if err != nil {
			t.Fatalf("create policy for %s: %v", assetName, err)
		}
		policyIDs = append(policyIDs, p.Msg.Policy.Id)
	}

	// Page 1: 2 of the 3 policies (newest first), must have a token.
	page1, err := acc.ListRequestPolicies(ctx, withToken(connect.NewRequest(&accessv1.ListRequestPoliciesRequest{
		RoleId: roleID, PageSize: 2,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Policies) != 2 {
		t.Fatalf("page1: got %d policies, want 2", len(page1.Msg.Policies))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}

	// Ordering: created_at DESC means asset-c policy (newest) is first.
	wantP1 := []string{policyIDs[2], policyIDs[1]}
	for i, want := range wantP1 {
		if page1.Msg.Policies[i].Id != want {
			t.Fatalf("page1[%d] = %s, want %s (newest-first order)", i, page1.Msg.Policies[i].Id, want)
		}
	}

	// Page 2: remaining 1 policy (asset-a, oldest), no token.
	page2, err := acc.ListRequestPolicies(ctx, withToken(connect.NewRequest(&accessv1.ListRequestPoliciesRequest{
		RoleId: roleID, PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Policies) != 1 {
		t.Fatalf("page2: got %d policies, want 1", len(page2.Msg.Policies))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Policies[0].Id != policyIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest policy)", page2.Msg.Policies[0].Id, policyIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, p := range page1.Msg.Policies {
		seen[p.Id] = true
	}
	for _, p := range page2.Msg.Policies {
		if seen[p.Id] {
			t.Fatalf("duplicate policy id %s across pages", p.Id)
		}
	}
}

// TestListPolicySubjectsKeysetPagination verifies time-ordered (created_at DESC, id ASC)
// keyset pagination for ListPolicySubjects. Seeds a policy with 3 group subjects,
// pages with page_size=2, and asserts newest-first ordering + token termination.
func TestListPolicySubjectsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "sub-role", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	policy, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            role.Msg.Role.Id,
		RequiredApprovals: 1,
	}), tok))
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	policyID := policy.Msg.Policy.Id

	// Add 3 group subjects to the policy in order (oldest = group-a).
	var subjectIDs []string
	for _, groupName := range []string{"sub-grp-a", "sub-grp-b", "sub-grp-c"} {
		g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: groupName}), tok))
		if err != nil {
			t.Fatalf("create group %s: %v", groupName, err)
		}
		s, err := acc.AddPolicySubject(ctx, withToken(connect.NewRequest(&accessv1.AddPolicySubjectRequest{
			PolicyId:       policyID,
			Kind:           "approver",
			SubjectGroupId: g.Msg.Group.Id,
		}), tok))
		if err != nil {
			t.Fatalf("add subject for %s: %v", groupName, err)
		}
		subjectIDs = append(subjectIDs, s.Msg.Id)
	}

	// Page 1: 2 of the 3 subjects (newest first), must have a token.
	page1, err := acc.ListPolicySubjects(ctx, withToken(connect.NewRequest(&accessv1.ListPolicySubjectsRequest{
		PolicyId: policyID, PageSize: 2,
	}), tok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Subjects) != 2 {
		t.Fatalf("page1: got %d subjects, want 2", len(page1.Msg.Subjects))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}

	// Ordering: created_at DESC means sub-grp-c subject (newest) is first.
	wantP1 := []string{subjectIDs[2], subjectIDs[1]}
	for i, want := range wantP1 {
		if page1.Msg.Subjects[i].Id != want {
			t.Fatalf("page1[%d] = %s, want %s (newest-first order)", i, page1.Msg.Subjects[i].Id, want)
		}
	}

	// Page 2: remaining 1 subject (sub-grp-a, oldest), no token.
	page2, err := acc.ListPolicySubjects(ctx, withToken(connect.NewRequest(&accessv1.ListPolicySubjectsRequest{
		PolicyId: policyID, PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Subjects) != 1 {
		t.Fatalf("page2: got %d subjects, want 1", len(page2.Msg.Subjects))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Subjects[0].Id != subjectIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest subject)", page2.Msg.Subjects[0].Id, subjectIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, s := range page1.Msg.Subjects {
		seen[s.Id] = true
	}
	for _, s := range page2.Msg.Subjects {
		if seen[s.Id] {
			t.Fatalf("duplicate subject id %s across pages", s.Id)
		}
	}
}
