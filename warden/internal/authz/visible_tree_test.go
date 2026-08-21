package authz

import (
	"context"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// toSet converts a uuid slice into a map[uuid.UUID]struct{} for set operations.
func toSet(ids []uuid.UUID) map[uuid.UUID]struct{} {
	s := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		s[id] = struct{}{}
	}
	return s
}

// idSet compares two id slices as sets (order-independent), reporting a readable
// diff on mismatch.
func idSet(t *testing.T, label string, got, want []uuid.UUID) {
	t.Helper()
	norm := func(xs []uuid.UUID) []string {
		ss := make([]string, len(xs))
		for i, x := range xs {
			ss[i] = x.String()
		}
		sort.Strings(ss)
		return ss
	}
	g, w := norm(got), norm(want)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", label, g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", label, g, w)
		}
	}
}

// seedTree builds the tier-matrix fixture:
//
//	folders   root ⊃ f1 ⊃ f2
//	assets    a1 ∈ f1, a2 ∈ f2
//	admin     scopeless (global) role with catalog:asset:read + catalog:folder:read
//	alice     standing connect role directly on a1 (active access, no management cap)
//	bob       a2 requestable via a request_policy naming bob's group as a requester
//	          subject (requestable access, no management cap, nothing on a1)
func seedTree(t *testing.T, pool *pgxpool.Pool) (admin, alice, bob, root, f1, f2, a1, a2 uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	adminU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "admin@tree", DisplayName: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	aliceU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "alice@tree", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	bobU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@tree", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}

	rootF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "root"})
	if err != nil {
		t.Fatal(err)
	}
	f1F, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "f1", ParentID: pgUUID(rootF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	f2F, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "f2", ParentID: pgUUID(f1F.ID)})
	if err != nil {
		t.Fatal(err)
	}
	a1A, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: f1F.ID, Name: "a1", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	a2A, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: f2F.ID, Name: "a2", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	// admin: scopeless (global) role carrying the two catalog read caps.
	adminRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "tree-admin", Capabilities: caps("catalog:asset:read", "catalog:folder:read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: adminRole.ID, SubjectUserID: pgUUID(adminU.ID), // no scope → global
	}); err != nil {
		t.Fatal(err)
	}

	// alice: standing connect role bound directly on a1 (active access, no mgmt cap).
	connect, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "tree-connect", Capabilities: caps("ssh:connect")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: connect.ID, ScopeAssetID: pgUUID(a1A.ID), SubjectUserID: pgUUID(aliceU.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// bob: a2 requestable via a policy naming bob (a group he's in) as a requester.
	bobs, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "tree-bobs"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: bobs.ID, MemberUserID: pgUUID(bobU.ID)}); err != nil {
		t.Fatal(err)
	}
	dba, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "tree-dba", Capabilities: caps("db:admin")})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: dba.ID, ScopeAssetID: pgUUID(a2A.ID), RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, gen.AddPolicySubjectParams{
		PolicyID: pol.ID, Kind: "requester", SubjectGroupID: pgUUID(bobs.ID),
	}); err != nil {
		t.Fatal(err)
	}

	return adminU.ID, aliceU.ID, bobU.ID, rootF.ID, f1F.ID, f2F.ID, a1A.ID, a2A.ID
}

// seedRolesGroups builds the role/group tier fixture on top of a fresh tree:
//
//	folders   root ⊃ f1
//	roles     groleG (folder NULL, global) + frole (@f1)
//	groups    ggroupG (folder NULL, global) + fgroup (@f1)
//	admin     global role carrying access:role:read + identity:group:read (management)
//	holder    standing binding conferring frole (access arm: held, no read cap)
//	member    member of fgroup (access arm: membership, no read cap)
//	stranger  nothing
//
// holder holds frole via a standing role_binding whose role_id IS frole (holding a
// role on any object makes it "held"); the binding is on a1 so it is a concrete
// object. member is added to fgroup via group_memberships.
func seedRolesGroups(t *testing.T, pool *pgxpool.Pool) (admin, holder, member, stranger, root, f1, groleG, frole, ggroupG, fgroup, adminRoleID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	rootF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "rg-root"})
	if err != nil {
		t.Fatal(err)
	}
	f1F, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "rg-f1", ParentID: pgUUID(rootF.ID)})
	if err != nil {
		t.Fatal(err)
	}

	// A global role (folder NULL) and a folder-homed role (@f1).
	groleGRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "rg-role-global", Capabilities: caps("ssh:connect")})
	if err != nil {
		t.Fatal(err)
	}
	froleRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "rg-frole", FolderID: pgUUID(f1F.ID), Capabilities: caps("ssh:connect"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A global group (folder NULL) and a folder-homed group (@f1).
	ggroupGGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "rg-group-global"})
	if err != nil {
		t.Fatal(err)
	}
	fgroupGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "rg-fgroup", FolderID: pgUUID(f1F.ID)})
	if err != nil {
		t.Fatal(err)
	}

	adminU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-admin@tree", DisplayName: "RGAdmin"})
	if err != nil {
		t.Fatal(err)
	}
	holderU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-holder@tree", DisplayName: "RGHolder"})
	if err != nil {
		t.Fatal(err)
	}
	memberU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-member@tree", DisplayName: "RGMember"})
	if err != nil {
		t.Fatal(err)
	}
	strangerU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-stranger@tree", DisplayName: "RGStranger"})
	if err != nil {
		t.Fatal(err)
	}

	// admin: global role carrying the two read caps (management arm, everywhere).
	adminRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "rg-admin-role", Capabilities: caps("access:role:read", "identity:group:read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: adminRole.ID, SubjectUserID: pgUUID(adminU.ID), // no scope → global
	}); err != nil {
		t.Fatal(err)
	}

	// holder: standing binding conferring frole on a folder (access arm: held).
	// Bound at f1 so the binding has a concrete object; holding frole on ANY object
	// makes it appear in heldRoleIDs.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: froleRole.ID, ScopeFolderID: pgUUID(f1F.ID), SubjectUserID: pgUUID(holderU.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// member: member of fgroup (access arm: transitive membership).
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{
		GroupID: fgroupGroup.ID, MemberUserID: pgUUID(memberU.ID),
	}); err != nil {
		t.Fatal(err)
	}

	return adminU.ID, holderU.ID, memberU.ID, strangerU.ID, rootF.ID, f1F.ID,
		groleGRole.ID, froleRole.ID, ggroupGGroup.ID, fgroupGroup.ID, adminRole.ID
}

func TestVisibleRolesUnderTiers(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, holder, _, stranger, _, f1, groleG, frole, _, _, adminRoleID := seedRolesGroups(t, pool)

	// admin (global access:role:read): whole tree cascade → every role. Besides the
	// two fixture roles this includes admin's OWN global role (adminRoleID), which is
	// visible on BOTH arms — management (global read cap) and access (admin holds it).
	got, err := s.VisibleRolesUnder(ctx, admin, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles admin nil cascade", got, []uuid.UUID{groleG, frole, adminRoleID})

	// admin non-cascade at root → the folder-less (global) roles: groleG (mgmt) and
	// admin's own held global role.
	got, err = s.VisibleRolesUnder(ctx, admin, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles admin nil no-cascade", got, []uuid.UUID{groleG, adminRoleID})

	// admin non-cascade at f1 → only frole (homed in f1).
	got, err = s.VisibleRolesUnder(ctx, admin, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles admin f1 no-cascade", got, []uuid.UUID{frole})

	// holder (access arm: holds frole, no read cap) at f1 → frole only.
	got, err = s.VisibleRolesUnder(ctx, holder, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles holder f1 no-cascade", got, []uuid.UUID{frole})

	// holder must NOT see the global role (no access to it, no global cap).
	got, err = s.VisibleRolesUnder(ctx, holder, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles holder nil no-cascade", got, nil)

	// stranger: nothing.
	got, err = s.VisibleRolesUnder(ctx, stranger, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "roles stranger nil cascade", got, nil)
}

func TestVisibleGroupsUnderTiers(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, _, member, stranger, _, f1, _, _, ggroupG, fgroup, _ := seedRolesGroups(t, pool)

	// admin (global identity:group:read): whole tree cascade → both groups.
	got, err := s.VisibleGroupsUnder(ctx, admin, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "groups admin nil cascade", got, []uuid.UUID{ggroupG, fgroup})

	// admin non-cascade at f1 → only fgroup (homed in f1).
	got, err = s.VisibleGroupsUnder(ctx, admin, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "groups admin f1 no-cascade", got, []uuid.UUID{fgroup})

	// member (access arm: member of fgroup, no read cap) at f1 → fgroup only.
	got, err = s.VisibleGroupsUnder(ctx, member, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "groups member f1 no-cascade", got, []uuid.UUID{fgroup})

	// member must NOT see the global group (not a member, no global cap).
	got, err = s.VisibleGroupsUnder(ctx, member, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "groups member nil no-cascade", got, nil)

	// stranger: nothing.
	got, err = s.VisibleGroupsUnder(ctx, stranger, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "groups stranger nil cascade", got, nil)
}

func TestVisibleAssetsUnder(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, alice, bob, root, f1, f2, a1, a2 := seedTree(t, pool)

	stranger, err := gen.New(pool).CreateUser(ctx, gen.CreateUserParams{Email: "stranger@tree", DisplayName: "S"})
	if err != nil {
		t.Fatal(err)
	}

	// ── VisibleAssetsUnder ────────────────────────────────────────────────────
	// admin holds catalog:asset:read globally → every asset under the subtree.
	got, err := s.VisibleAssetsUnder(ctx, admin, f1, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets admin f1 cascade", got, []uuid.UUID{a1, a2})

	// non-cascade under f1 → only a1 (a1 lives in f1; a2 lives in f2).
	got, err = s.VisibleAssetsUnder(ctx, admin, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets admin f1 no-cascade", got, []uuid.UUID{a1})

	// alice: standing access on a1 only → sees a1, not a2.
	got, err = s.VisibleAssetsUnder(ctx, alice, f1, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets alice f1 cascade", got, []uuid.UUID{a1})

	// bob: a2 requestable → sees a2 under f2 (no cascade needed, a2 is directly in f2).
	got, err = s.VisibleAssetsUnder(ctx, bob, f2, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets bob f2 no-cascade", got, []uuid.UUID{a2})

	// stranger: nothing → no assets.
	got, err = s.VisibleAssetsUnder(ctx, stranger.ID, root, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets stranger root cascade", got, nil)

	// root without cascade → no assets (assets always live in a folder).
	got, err = s.VisibleAssetsUnder(ctx, admin, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "assets admin root(nil) no-cascade", got, nil)

	// ── VisibleFoldersUnder ───────────────────────────────────────────────────
	// bob: f1 visible because its subtree (f2) holds bob's accessible a2. f2 is not
	// a child of root, so it does not appear at the root level.
	gotF, err := s.VisibleFoldersUnder(ctx, bob, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "folders bob root no-cascade", gotF, []uuid.UUID{f1})

	// admin holds catalog:folder:read globally → all level folders.
	gotF, err = s.VisibleFoldersUnder(ctx, admin, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "folders admin root no-cascade", gotF, []uuid.UUID{f1})
	gotF, err = s.VisibleFoldersUnder(ctx, admin, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "folders admin f1 no-cascade", gotF, []uuid.UUID{f2})

	// alice: a1 in f1 → f1 visible via the access arm.
	gotF, err = s.VisibleFoldersUnder(ctx, alice, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "folders alice root no-cascade", gotF, []uuid.UUID{f1})

	// stranger: nothing → no folders.
	gotF, err = s.VisibleFoldersUnder(ctx, stranger.ID, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "folders stranger root no-cascade", gotF, nil)
}

// TestVisibleScopedNonGlobalAdmin pins that a user whose catalog read caps are
// bound at folder f1 ONLY (not globally) sees assets/folders in f1 and its
// descendant f2 (caps cascade structurally down via CapabilitiesOnScope ancestor
// walk) but does NOT see a sibling folder f3 or its asset a3.  This verifies
// that the global short-circuit in VisibleAssetsUnder/VisibleFoldersUnder does
// not over-include and that scoped caps do not leak sideways.
func TestVisibleScopedNonGlobalAdmin(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	// Tree: root ⊃ f1 ⊃ f2  (from seedTree) + root ⊃ f3
	_, _, _, root, f1, f2, a1, a2 := seedTree(t, pool)

	f3F, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "vt-f3", ParentID: pgUUID(root)})
	if err != nil {
		t.Fatal(err)
	}
	f3 := f3F.ID
	a3A, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: f3, Name: "vt-a3", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	a3 := a3A.ID

	// scopedAdmin holds catalog:asset:read + catalog:folder:read bound at f1 ONLY.
	scopedAdminU, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "scoped-admin@vt", DisplayName: "ScopedAdmin"})
	if err != nil {
		t.Fatal(err)
	}
	scopedRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "vt-scoped-admin", Capabilities: caps("catalog:asset:read", "catalog:folder:read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: scopedRole.ID, ScopeFolderID: pgUUID(f1), SubjectUserID: pgUUID(scopedAdminU.ID),
	}); err != nil {
		t.Fatal(err)
	}
	u := scopedAdminU.ID

	// Assets under f1 cascade: should see a1 (in f1) and a2 (in f2, descendant of f1).
	got, err := s.VisibleAssetsUnder(ctx, u, f1, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: assets under f1 cascade", got, []uuid.UUID{a1, a2})

	// Non-cascade under f1: only a1 (directly in f1).
	got, err = s.VisibleAssetsUnder(ctx, u, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: assets under f1 no-cascade", got, []uuid.UUID{a1})

	// Folders directly under f1 (non-cascade): only f2.
	gotF, err := s.VisibleFoldersUnder(ctx, u, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: folders under f1 no-cascade", gotF, []uuid.UUID{f2})

	// Caps must NOT leak to the sibling branch f3/a3: assets under f3 (cascade).
	got, err = s.VisibleAssetsUnder(ctx, u, f3, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: assets under f3 cascade (should be empty)", got, nil)
	_ = a3 // created to confirm it exists in f3 but is invisible to the scoped admin

	// Folders under root: the scoped cap on f1 still covers f1 itself (ancestor
	// walk), so f1 should be visible; f3 must NOT be (no binding there).
	gotF, err = s.VisibleFoldersUnder(ctx, u, root, false)
	if err != nil {
		t.Fatal(err)
	}
	// f1 is visible (scoped cap on f1 ⇒ CapabilitiesOnScope(FolderScope(f1)) hits
	// it directly); f3 is a sibling with no matching binding.
	if set := toSet(gotF); !contains(set, f1) {
		t.Fatalf("scoped admin: f1 must be visible under root; got %v", gotF)
	}
	if set := toSet(gotF); contains(set, f3) {
		t.Fatalf("scoped admin: f3 must NOT be visible under root (no binding); got %v", gotF)
	}
}

// contains is a map membership helper used by the regression tests.
func contains(s map[uuid.UUID]struct{}, id uuid.UUID) bool {
	_, ok := s[id]
	return ok
}

// TestVisibleManageOnlyEmptyFolder pins that an empty folder (no assets) still
// appears in VisibleFoldersUnder for a user with global catalog:folder:read —
// the management arm fires even when the access arm (subtree assets) is empty.
func TestVisibleManageOnlyEmptyFolder(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	admin, _, _, root, f1, _, _, _ := seedTree(t, pool)

	// Empty folder fe under root — no assets, no sub-folders.
	feF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "vt-fe", ParentID: pgUUID(root)})
	if err != nil {
		t.Fatal(err)
	}
	fe := feF.ID

	// admin is globally bound with catalog:folder:read (from seedTree).
	// VisibleFoldersUnder(root, false) must include BOTH f1 and fe (pure mgmt arm).
	gotF, err := s.VisibleFoldersUnder(ctx, admin, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "manage-only empty folder: admin sees f1 and fe under root", gotF, []uuid.UUID{f1, fe})
}

// TestVisibleNonexistentParent pins that passing a random uuid as the parent id
// returns empty slices without error (no crash, no false positives).
func TestVisibleNonexistentParent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, _, _, _, _, _, _, _ := seedTree(t, pool)

	ghost := uuid.New()

	got, err := s.VisibleAssetsUnder(ctx, admin, ghost, true)
	if err != nil {
		t.Fatalf("VisibleAssetsUnder nonexistent parent: %v", err)
	}
	idSet(t, "assets nonexistent parent cascade", got, nil)

	gotF, err := s.VisibleFoldersUnder(ctx, admin, ghost, false)
	if err != nil {
		t.Fatalf("VisibleFoldersUnder nonexistent parent: %v", err)
	}
	idSet(t, "folders nonexistent parent no-cascade", gotF, nil)
}

// TestVisibleLeafFolderHasNoChildren pins that VisibleFoldersUnder on a leaf
// folder (f2 has no child folders in the seedTree fixture) returns empty without
// error.
func TestVisibleLeafFolderHasNoChildren(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, _, _, _, _, f2, _, _ := seedTree(t, pool)

	gotF, err := s.VisibleFoldersUnder(ctx, admin, f2, false)
	if err != nil {
		t.Fatalf("VisibleFoldersUnder leaf f2: %v", err)
	}
	idSet(t, "folders leaf f2 no-cascade", gotF, nil)
}

// TestVisibleCascadeNoDuplicates pins that VisibleAssetsUnder with cascade=true
// from the root returns each asset id exactly once, even when overlapping subtree
// paths could theoretically produce duplicates.
func TestVisibleCascadeNoDuplicates(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, _, _, _, _, _, a1, a2 := seedTree(t, pool)

	// Cascade from uuid.Nil (root sentinel) covers the whole tree.
	got, err := s.VisibleAssetsUnder(ctx, admin, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}

	// The fixture has exactly two assets (a1, a2).  Verify len equals the distinct
	// count (no duplicates) and that both ids are present.
	distinct := toSet(got)
	if len(got) != len(distinct) {
		t.Fatalf("cascade dedup: got %d results but only %d distinct ids: %v", len(got), len(distinct), got)
	}
	idSet(t, "cascade root no-duplicates", got, []uuid.UUID{a1, a2})
}

// TestVisibleDeactivatedRoleHolder pins that a user who holds a folder-homed role
// via a standing role_binding loses all role visibility after deactivation.
// This test pins the role arm of VisibleRolesUnder (already guarded by heldCTE).
func TestVisibleDeactivatedRoleHolder(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	_, _, _, _, _, f1, _, frole, _, _, _ := seedRolesGroups(t, pool)

	// Create a new user (separate from the seed's holder) with a standing binding
	// conferring frole on f1 so we can deactivate without disturbing the seed.
	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "deact-role-holder@vt", DisplayName: "DeactRoleHolder"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: frole, ScopeFolderID: pgUUID(f1), SubjectUserID: pgUUID(u.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Pre-deactivation: frole is visible via the access arm (held).
	got, err := s.VisibleRolesUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "pre-deactivation: roles under f1", got, []uuid.UUID{frole})

	// Deactivate: all role visibility must vanish.
	deactivateUser(t, pool, u.ID)

	got, err = s.VisibleRolesUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: roles under f1", got, nil)
}

// TestVisibleDeactivatedGroupMember is the regression lock for the
// memberGroupIDs deactivation bug: a user who is a transitive member of a
// folder-homed group must NOT see that group via VisibleGroupsUnder after
// deactivation. Without the EXISTS guard in memberGroupIDs this test FAILS
// (the query returns group_ids regardless of deactivated_at); with the guard
// it passes.
func TestVisibleDeactivatedGroupMember(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	_, _, _, _, _, f1, _, _, _, fgroup, _ := seedRolesGroups(t, pool)

	// Create a new user and add them to fgroup so we can deactivate independently.
	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "deact-group-member@vt", DisplayName: "DeactGroupMember"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: fgroup, MemberUserID: pgUUID(u.ID)}); err != nil {
		t.Fatal(err)
	}

	// Pre-deactivation: fgroup is visible via the access arm (membership).
	got, err := s.VisibleGroupsUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "pre-deactivation: groups under f1", got, []uuid.UUID{fgroup})

	// Deactivate: the group membership arm must yield nothing.
	deactivateUser(t, pool, u.ID)

	got, err = s.VisibleGroupsUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: groups under f1", got, nil)
}

// TestVisibleScopedNonGlobalAdminRolesGroups pins that a user with
// "access:role:read" + "identity:group:read" bound ONLY at folder f1 (not
// globally) sees f1-homed roles and groups but NOT folder-less (global) nodes
// (those require the global cap) and NOT a sibling folder's roles/groups.
func TestVisibleScopedNonGlobalAdminRolesGroups(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	_, _, _, _, root, f1, _, frole, _, fgroup, _ := seedRolesGroups(t, pool)

	// Create f-other as a sibling of f1 under rg-root, with its own role+group.
	fOtherF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "rg-f-other", ParentID: pgUUID(root)})
	if err != nil {
		t.Fatal(err)
	}
	fOther := fOtherF.ID
	fOtherRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "rg-other-role", FolderID: pgUUID(fOther), Capabilities: caps("ssh:connect"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fOtherGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{
		Name: "rg-other-group", FolderID: pgUUID(fOther),
	})
	if err != nil {
		t.Fatal(err)
	}

	// scopedAdmin: access:role:read + identity:group:read bound ONLY at f1.
	// mgmtRole is itself homed in f1 (not folder-less), so it will not appear in
	// the folder-less (global) candidate list and cannot be seen via the management
	// arm at the global level.
	scopedAdmin, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-scoped-admin@vt", DisplayName: "RGScopedAdmin"})
	if err != nil {
		t.Fatal(err)
	}
	mgmtRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "rg-scoped-mgmt", FolderID: pgUUID(f1),
		Capabilities: caps("access:role:read", "identity:group:read"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: mgmtRole.ID, ScopeFolderID: pgUUID(f1), SubjectUserID: pgUUID(scopedAdmin.ID),
	}); err != nil {
		t.Fatal(err)
	}
	u := scopedAdmin.ID

	// Roles under f1 (non-cascade): frole is visible via management arm
	// (access:role:read at f1); mgmtRole is visible via the access arm (user holds
	// it). Both are f1-homed nodes.
	gotR, err := s.VisibleRolesUnder(ctx, u, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: roles under f1 no-cascade", gotR, []uuid.UUID{frole, mgmtRole.ID})

	// Groups under f1 (non-cascade): fgroup is f1-homed → visible via management arm.
	gotG, err := s.VisibleGroupsUnder(ctx, u, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: groups under f1 no-cascade", gotG, []uuid.UUID{fgroup})

	// Roles at global level (uuid.Nil, non-cascade): folder-less nodes require the
	// global cap which this user does NOT hold. mgmtRole is homed in f1, not
	// folder-less, so it does not appear here. The seed's groleG is folder-less but
	// the user neither holds it nor has the global cap → empty.
	gotR, err = s.VisibleRolesUnder(ctx, u, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: roles at global level (no global cap)", gotR, nil)

	// Groups at global level: same reasoning → empty.
	gotG, err = s.VisibleGroupsUnder(ctx, u, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "scoped admin: groups at global level (no global cap)", gotG, nil)

	// Roles under f-other (sibling): no binding there → empty (no sideways leak).
	gotR, err = s.VisibleRolesUnder(ctx, u, fOther, false)
	if err != nil {
		t.Fatal(err)
	}
	if set := toSet(gotR); contains(set, fOtherRole.ID) {
		t.Fatalf("scoped admin: f-other role must NOT be visible (sibling leak); got %v", gotR)
	}

	// Groups under f-other (sibling): same.
	gotG, err = s.VisibleGroupsUnder(ctx, u, fOther, false)
	if err != nil {
		t.Fatal(err)
	}
	if set := toSet(gotG); contains(set, fOtherGroup.ID) {
		t.Fatalf("scoped admin: f-other group must NOT be visible (sibling leak); got %v", gotG)
	}
}

// TestVisibleNestedSubgroupMember pins that transitive group membership is
// reflected in VisibleGroupsUnder: a user who is a direct member of childGroup,
// where childGroup is itself a member of parentGroup (both homed in f1), sees
// BOTH groups via the access arm (transitive membership closure).
func TestVisibleNestedSubgroupMember(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	_, _, _, _, _, f1, _, _, _, _, _ := seedRolesGroups(t, pool)

	// Create a parent+child group pair both homed in f1.
	childGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{
		Name: "rg-nested-child", FolderID: pgUUID(f1),
	})
	if err != nil {
		t.Fatal(err)
	}
	parentGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{
		Name: "rg-nested-parent", FolderID: pgUUID(f1),
	})
	if err != nil {
		t.Fatal(err)
	}
	// childGroup is a member of parentGroup (nested group membership).
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{
		GroupID: parentGroup.ID, MemberGroupID: pgUUID(childGroup.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Create a user who is a direct member of childGroup only.
	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "rg-nested-user@vt", DisplayName: "RGNestedUser"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{
		GroupID: childGroup.ID, MemberUserID: pgUUID(u.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// VisibleGroupsUnder(f1, false) must include BOTH childGroup and parentGroup
	// via transitive membership — the access arm of VisibleGroupsUnder walks the
	// full user_groups CTE closure.
	got, err := s.VisibleGroupsUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	if set := toSet(got); !contains(set, childGroup.ID) {
		t.Fatalf("nested member: childGroup must be visible; got %v", got)
	}
	if set := toSet(got); !contains(set, parentGroup.ID) {
		t.Fatalf("nested member: parentGroup must be visible (transitive); got %v", got)
	}
}

// TestVisibleDeactivatedUserStandingBinding pins that a deactivated user who
// previously held a standing connect binding on an asset loses all visibility:
// VisibleAssetsUnder and VisibleFoldersUnder both return empty after deactivation.
func TestVisibleDeactivatedUserStandingBinding(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	_, _, _, root, f1, _, a1, _ := seedTree(t, pool)

	// Create a new user with a standing connect binding on a1.
	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "deact-vis@vt", DisplayName: "DeactVis"})
	if err != nil {
		t.Fatal(err)
	}
	connectRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "vt-deact-connect", Capabilities: caps("ssh:connect"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: connectRole.ID, ScopeAssetID: pgUUID(a1), SubjectUserID: pgUUID(u.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Pre-deactivation: user can see a1 via the access arm (standing connect binding).
	got, err := s.VisibleAssetsUnder(ctx, u.ID, f1, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "pre-deactivation: assets under f1", got, []uuid.UUID{a1})

	// f1 is also visible (browse path to a1).
	gotF, err := s.VisibleFoldersUnder(ctx, u.ID, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "pre-deactivation: folders under root", gotF, []uuid.UUID{f1})

	// Deactivate: all visibility must vanish immediately (no reaper needed).
	deactivateUser(t, pool, u.ID)

	got, err = s.VisibleAssetsUnder(ctx, u.ID, f1, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: assets under f1 cascade", got, nil)

	gotF, err = s.VisibleFoldersUnder(ctx, u.ID, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: folders under root", gotF, nil)
}

// TestIsMember verifies IsMember: direct member returns true; transitive
// (nested) member returns true; non-member returns false; deactivated member
// returns false.
func TestIsMember(t *testing.T) {
	pool := newPool(t)
	s := NewSQLAuthorizer(pool)
	ctx := context.Background()
	q := gen.New(pool)

	alice, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "alice@member", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@member", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	// deactivated user
	carol, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "carol@member", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}

	inner, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "inner"})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "outer"})
	if err != nil {
		t.Fatal(err)
	}

	// alice is a direct member of inner.
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: inner.ID, MemberUserID: pgUUID(alice.ID)}); err != nil {
		t.Fatal(err)
	}
	// inner is nested inside outer (alice is a transitive member of outer).
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: outer.ID, MemberGroupID: pgUUID(inner.ID)}); err != nil {
		t.Fatal(err)
	}
	// carol is a direct member of inner but will be deactivated.
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: inner.ID, MemberUserID: pgUUID(carol.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.DeactivateUser(ctx, carol.ID); err != nil {
		t.Fatal(err)
	}

	// alice: direct member of inner → true.
	ok, err := s.IsMember(ctx, alice.ID, inner.ID)
	if err != nil {
		t.Fatalf("IsMember(alice, inner): %v", err)
	}
	if !ok {
		t.Fatal("alice should be a direct member of inner")
	}

	// alice: transitive member of outer → true.
	ok, err = s.IsMember(ctx, alice.ID, outer.ID)
	if err != nil {
		t.Fatalf("IsMember(alice, outer): %v", err)
	}
	if !ok {
		t.Fatal("alice should be a transitive member of outer (via inner)")
	}

	// bob: not a member of either group → false.
	ok, err = s.IsMember(ctx, bob.ID, inner.ID)
	if err != nil {
		t.Fatalf("IsMember(bob, inner): %v", err)
	}
	if ok {
		t.Fatal("bob should NOT be a member of inner")
	}

	// carol: deactivated member → false.
	ok, err = s.IsMember(ctx, carol.ID, inner.ID)
	if err != nil {
		t.Fatalf("IsMember(carol, inner): %v", err)
	}
	if ok {
		t.Fatal("deactivated carol should NOT appear as a member")
	}
}
