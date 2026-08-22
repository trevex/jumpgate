package rpc_test

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// TestListFoldersParentScoped: admin browses root and children; a requester who
// can reach an asset under f1 sees f1 (its path to the asset is not hidden) but
// not an empty sibling f2.
func TestListFoldersParentScoped(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustF := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.Folder.Id
	}
	mustA := func(folder, name string) string {
		r, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: folder, Name: name, Config: emptySSHConfig()}), tok))
		if err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return r.Msg.Asset.Id
	}

	f1 := mustF("prod", "")
	child := mustF("db", f1)
	mustA(child, "box-1")
	f2 := mustF("secret", "")
	mustA(f2, "top-secret")

	// ── admin ──────────────────────────────────────────────────────────────────
	// Root, non-cascade: the two top-level folders (prod, secret) only.
	roots, err := cat.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{}), tok))
	if err != nil {
		t.Fatalf("admin list roots: %v", err)
	}
	if got := folderIDSet(roots.Msg.Folders); !got[f1] || !got[f2] || got[child] {
		t.Fatalf("admin root folders = %v, want {prod,secret} without db", got)
	}
	// Under f1, non-cascade: only the direct child db.
	kids, err := cat.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{Parent: f1}), tok))
	if err != nil {
		t.Fatalf("admin list children: %v", err)
	}
	if got := folderIDSet(kids.Msg.Folders); !got[child] || got[f1] {
		t.Fatalf("admin children of f1 = %v, want {db}", got)
	}

	// ── requester alice ─────────────────────────────────────────────────────────
	alice, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "alice@x", DisplayName: "Alice", Password: "password123"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	role, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "ro", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	// role cascades down folders (parent self-rule).
	rid := uuid.MustParse(role.Msg.Role.Id)
	if _, err := gen.New(pool).CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: rid, SourceRoleID: rid, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// Standing binding: alice -> ro on folder f1 (so the box-1 asset under f1/db is active).
	if _, err := access.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f1, SubjectUserId: alice.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatal(err)
	}

	atok := authClient(t, url, "alice@x", "password123")
	// alice at root cascade: sees f1 and its child db (the path to her asset), not f2.
	av, err := cat.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{Cascade: true}), atok))
	if err != nil {
		t.Fatalf("alice list: %v", err)
	}
	got := folderIDSet(av.Msg.Folders)
	if !got[f1] || !got[child] {
		t.Fatalf("alice folders = %v, want f1+db (path to her asset)", got)
	}
	if got[f2] {
		t.Fatalf("alice must not see empty sibling secret folder: %v", got)
	}
}

// TestListAssetsUnified: admin cascade from root sees every asset; a requester sees
// a strict subset; parent-scoped (non-cascade) returns the folder's direct assets.
func TestListAssetsUnified(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	access := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustF := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.Folder.Id
	}
	mustA := func(folder, name string) string {
		r, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: folder, Name: name, Config: emptySSHConfig()}), tok))
		if err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return r.Msg.Asset.Id
	}

	f1 := mustF("prod", "")
	child := mustF("db", f1)
	a1 := mustA(f1, "box-1")
	a2 := mustA(child, "box-2")
	f2 := mustF("secret", "")
	a3 := mustA(f2, "top-secret")

	// admin cascade from root: all three assets.
	all, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Cascade: true}), tok))
	if err != nil {
		t.Fatalf("admin cascade: %v", err)
	}
	if got := assetIDSet(all.Msg.Assets); !got[a1] || !got[a2] || !got[a3] {
		t.Fatalf("admin cascade assets = %v, want all three", got)
	}
	// admin parent-scoped non-cascade under f1: only a1 (a2 is in the child folder).
	direct, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: f1}), tok))
	if err != nil {
		t.Fatalf("admin direct: %v", err)
	}
	if got := assetIDSet(direct.Msg.Assets); !got[a1] || got[a2] {
		t.Fatalf("admin direct under f1 = %v, want {box-1} only", got)
	}

	// requester alice: standing role on f1 (cascades to a1 and a2), never f2/a3.
	alice, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "alice@x", DisplayName: "Alice", Password: "password123"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	role, err := access.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{Name: "ro", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	rid := uuid.MustParse(role.Msg.Role.Id)
	if _, err := gen.New(pool).CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: rid, SourceRoleID: rid, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	if _, err := access.CreateRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, ScopeFolderId: f1, SubjectUserId: alice.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatal(err)
	}
	atok := authClient(t, url, "alice@x", "password123")
	av, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Cascade: true}), atok))
	if err != nil {
		t.Fatalf("alice cascade: %v", err)
	}
	got := assetIDSet(av.Msg.Assets)
	if !got[a1] || !got[a2] {
		t.Fatalf("alice assets = %v, want box-1+box-2", got)
	}
	if got[a3] {
		t.Fatalf("alice must not see top-secret (strict subset): %v", got)
	}
}

// TestGetAssetAccessCapabilities: GetAssetAccess surfaces the caller's data-plane
// (connect) capabilities on the asset. ConnectCapabilities reads the full scope
// cascade (global + ancestor folders + asset) minus the literal ** super-cap, so a
// user holding a catalog:asset:read capability bound to the asset sees exactly that
// entry. (An admin's GLOBAL ** would be stripped by the carve-out and so still does
// not appear — the response mirrors connect ability, not management authority.)
func TestGetAssetAccessCapabilities(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	a, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: "box", Config: emptySSHConfig()}), tok))
	if err != nil {
		t.Fatal(err)
	}
	assetID := uuid.MustParse(a.Msg.Asset.Id)

	// User holds catalog:asset:read bound directly at the asset scope.
	seedCapUserScoped(t, pool, "reader@x", "password123", `["catalog:asset:read"]`, uuid.Nil, assetID)
	rtok := authClient(t, url, "reader@x", "password123")
	acc, err := cat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: a.Msg.Asset.Id}), rtok))
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	if !contains(acc.Msg.Capabilities, "catalog:asset:read") {
		t.Fatalf("reader caps = %v, want a catalog:asset:read entry", acc.Msg.Capabilities)
	}
}

// TestGetFolderAccess: an admin gets folder capabilities (its ** wildcard, which
// CapabilitiesOnScope surfaces as a global cap on any scope); a stranger with no
// relationship to the folder gets NotFound (existence hiding).
func TestGetFolderAccess(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	// admin: CapabilitiesOnScope on the folder surfaces the admin's global ** wildcard.
	acc, err := cat.GetFolderAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetFolderAccessRequest{FolderId: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("admin folder access: %v", err)
	}
	if len(acc.Msg.Capabilities) == 0 {
		t.Fatalf("admin folder caps = %v, want non-empty (holds **)", acc.Msg.Capabilities)
	}

	// A folder-scoped cap holder sees exactly their concrete capability.
	seedCapUserScoped(t, pool, "fadmin@x", "password123", `["catalog:folder:read"]`, uuid.MustParse(f.Msg.Folder.Id), uuid.Nil)
	ftok := authClient(t, url, "fadmin@x", "password123")
	facc, err := cat.GetFolderAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetFolderAccessRequest{FolderId: f.Msg.Folder.Id}), ftok))
	if err != nil {
		t.Fatalf("folder-admin folder access: %v", err)
	}
	if !contains(facc.Msg.Capabilities, "catalog:folder:read") {
		t.Fatalf("folder-admin caps = %v, want catalog:folder:read", facc.Msg.Capabilities)
	}

	// stranger: capless, no relationship -> NotFound.
	seedCapUser(t, pool, "stranger@x", "password123", `[]`)
	stok := authClient(t, url, "stranger@x", "password123")
	if _, err := cat.GetFolderAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetFolderAccessRequest{FolderId: f.Msg.Folder.Id}), stok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("stranger folder access = %v, want NotFound", connect.CodeOf(err))
	}
}

// TestListFoldersDescendantVisibleParentGate: a user holding catalog:folder:read
// bound ONLY on a descendant folder (not on the parent, not on any asset) must
// be able to browse the parent — resolveParentFolder's third arm (VisibleFoldersUnder)
// must admit the parent rather than returning NotFound.
//
// Setup: prod→db; user has catalog:folder:read scoped to db only.
// Assert: ListFolders(parent="prod") succeeds and returns db (not NotFound).
func TestListFoldersDescendantVisibleParentGate(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create prod→db folder tree (no assets anywhere).
	prod, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create prod: %v", err)
	}
	prodID := uuid.MustParse(prod.Msg.Folder.Id)
	db, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db", ParentId: prod.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	dbID := uuid.MustParse(db.Msg.Folder.Id)

	// Seed a user with catalog:folder:read bound at db scope only (not prod, no assets).
	// seedCapUserScoped binds the role at folder scope when scopeFolder != uuid.Nil.
	_ = seedCapUserScoped(t, pool, "descendant@x", "password123", `["catalog:folder:read"]`, dbID, uuid.Nil)
	dtok := authClient(t, url, "descendant@x", "password123")

	// ListFolders(parent=prod) must NOT return NotFound — the user can see db (a
	// direct child of prod), so prod itself is visible as a navigable parent.
	kids, err := cat.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{Parent: prod.Msg.Folder.Id}), dtok))
	if err != nil {
		t.Fatalf("descendant ListFolders(parent=prod): got error %v, want success", err)
	}
	got := folderIDSet(kids.Msg.Folders)
	if !got[dbID.String()] {
		t.Fatalf("descendant folders under prod = %v, want db (%s)", got, dbID)
	}
	// prod itself must not appear as its own child.
	if got[prodID.String()] {
		t.Fatalf("prod must not appear as its own child")
	}
}

// TestListAssetsPagination: keyset pagination round-trip for ListAssets. Creates
// three assets in a folder with names out of alphabetical order (to prove
// server-side name ordering), requests them two at a time, and verifies:
//   - page1 has exactly 2 assets in ascending name order + a non-empty next_page_token
//   - page2 has the remaining asset + an empty next_page_token
//   - no duplicates, and the union equals all created assets in ascending name order
func TestListAssetsPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "paged"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	fid := f.Msg.Folder.Id

	// Create assets with names deliberately out of alphabetical order.
	mustA := func(name string) string {
		r, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fid, Name: name, Config: emptySSHConfig()}), tok))
		if err != nil {
			t.Fatalf("create asset %s: %v", name, err)
		}
		return r.Msg.Asset.Id
	}
	zID := mustA("zebra")
	aID := mustA("alpha")
	mID := mustA("mango")

	wantOrder := []string{aID, mID, zID} // ascending name order: alpha < mango < zebra

	// Page 1: page_size=2 → first two in name order (alpha, mango).
	p1, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: fid, PageSize: 2}), tok))
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Msg.Assets) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(p1.Msg.Assets))
	}
	if p1.Msg.NextPageToken == "" {
		t.Fatal("page1 next_page_token must be non-empty")
	}
	// Verify page1 order.
	if p1.Msg.Assets[0].Id != wantOrder[0] || p1.Msg.Assets[1].Id != wantOrder[1] {
		t.Fatalf("page1 order = [%s, %s], want [alpha=%s, mango=%s]",
			p1.Msg.Assets[0].Id, p1.Msg.Assets[1].Id, wantOrder[0], wantOrder[1])
	}

	// Page 2: continue from token → remaining one asset (zebra).
	p2, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{
		Parent: fid, PageSize: 2, PageToken: p1.Msg.NextPageToken,
	}), tok))
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(p2.Msg.Assets) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(p2.Msg.Assets))
	}
	if p2.Msg.NextPageToken != "" {
		t.Fatalf("page2 next_page_token = %q, want empty (last page)", p2.Msg.NextPageToken)
	}
	if p2.Msg.Assets[0].Id != wantOrder[2] {
		t.Fatalf("page2 asset = %s, want zebra=%s", p2.Msg.Assets[0].Id, wantOrder[2])
	}

	// No duplicates and union matches all created assets in ascending name order.
	all := append(p1.Msg.Assets, p2.Msg.Assets...)
	gotIDs := make([]string, len(all))
	for i, a := range all {
		gotIDs[i] = a.Id
	}
	sort.Strings(gotIDs)
	wantSorted := []string{aID, mID, zID}
	sort.Strings(wantSorted)
	for i := range wantSorted {
		if gotIDs[i] != wantSorted[i] {
			t.Fatalf("union mismatch at %d: got %s want %s", i, gotIDs[i], wantSorted[i])
		}
	}
}

// TestListFolderContents exercises the aggregator RPC:
//  1. Seed one subfolder, one asset, one folder-scoped role, and one folder-scoped
//     group under a parent folder F; as admin, assert the response contains exactly
//     one of each kind with all four *_has_more flags false.
//  2. Seed 51 assets under F (on top of the initial 1); assert assets_has_more is
//     true and exactly 50 assets are returned (all other *_has_more remain false).
func TestListFolderContents(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	idSvc := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Create parent folder F.
	fResp, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "contents"}), tok))
	if err != nil {
		t.Fatalf("create parent folder: %v", err)
	}
	fID := fResp.Msg.Folder.Id

	// Seed one child of each kind under F.
	_, err = cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "child", ParentId: fID}), tok))
	if err != nil {
		t.Fatalf("create subfolder: %v", err)
	}
	_, err = cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fID, Name: "box", Config: emptySSHConfig()}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	_, err = acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "contents-role", FolderId: fID, Capabilities: []string{"ssh:login:deploy"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	_, err = idSvc.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{
		Name: "contents-group", FolderId: fID,
	}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// ── basic: exactly one of each kind, no has_more ──────────────────────────
	basic, err := cat.ListFolderContents(ctx, withToken(connect.NewRequest(&catalogv1.ListFolderContentsRequest{Parent: fID}), tok))
	if err != nil {
		t.Fatalf("ListFolderContents (basic): %v", err)
	}
	if len(basic.Msg.Folders) != 1 {
		t.Errorf("basic: want 1 folder, got %d", len(basic.Msg.Folders))
	}
	if basic.Msg.FoldersHasMore {
		t.Error("basic: FoldersHasMore must be false")
	}
	if len(basic.Msg.Assets) != 1 {
		t.Errorf("basic: want 1 asset, got %d", len(basic.Msg.Assets))
	}
	if basic.Msg.AssetsHasMore {
		t.Error("basic: AssetsHasMore must be false")
	}
	if len(basic.Msg.Roles) != 1 {
		t.Errorf("basic: want 1 role, got %d", len(basic.Msg.Roles))
	}
	if basic.Msg.RolesHasMore {
		t.Error("basic: RolesHasMore must be false")
	}
	if len(basic.Msg.Groups) != 1 {
		t.Errorf("basic: want 1 group, got %d", len(basic.Msg.Groups))
	}
	if basic.Msg.GroupsHasMore {
		t.Error("basic: GroupsHasMore must be false")
	}

	// ── overflow: seed 51 more assets (1 already exists → total 52) ──────────
	for i := 0; i < 51; i++ {
		name := fmt.Sprintf("overflow-%03d", i)
		_, err = cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fID, Name: name, Config: emptySSHConfig()}), tok))
		if err != nil {
			t.Fatalf("seed overflow asset %d: %v", i, err)
		}
	}
	over, err := cat.ListFolderContents(ctx, withToken(connect.NewRequest(&catalogv1.ListFolderContentsRequest{Parent: fID}), tok))
	if err != nil {
		t.Fatalf("ListFolderContents (overflow): %v", err)
	}
	if len(over.Msg.Assets) != 50 {
		t.Errorf("overflow: want 50 assets, got %d", len(over.Msg.Assets))
	}
	if !over.Msg.AssetsHasMore {
		t.Error("overflow: AssetsHasMore must be true")
	}
	// Other kinds are unaffected by the asset overflow.
	if over.Msg.FoldersHasMore {
		t.Error("overflow: FoldersHasMore must still be false")
	}
	if over.Msg.RolesHasMore {
		t.Error("overflow: RolesHasMore must still be false")
	}
	if over.Msg.GroupsHasMore {
		t.Error("overflow: GroupsHasMore must still be false")
	}
}

func folderIDSet(fs []*catalogv1.Folder) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Id] = true
	}
	return m
}

func assetIDSet(as []*catalogv1.Asset) map[string]bool {
	m := map[string]bool{}
	for _, a := range as {
		m[a.Id] = true
	}
	return m
}
