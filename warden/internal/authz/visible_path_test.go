package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// governedOf returns the Governed flag of the folder `id` in v, and whether it was
// present at all.
func governedOf(v []VisibleFolder, id uuid.UUID) (governed, present bool) {
	for _, f := range v {
		if f.ID == id {
			return f.Governed, true
		}
	}
	return false, false
}

// seedPathReveal builds the path-reveal fixture used by the mgmt-cap tests:
//
//	folders   root ⊃ team   and   root ⊃ other  (team and other are siblings)
//	user      bound a role carrying `capabilities` at folder team ONLY.
//
// `team` is an empty leaf (no assets/sub-folders), so the ONLY thing that can make
// it — and its ancestor root — visible is the management-cap anchor at team. `other`
// has no anchor at/under it and must never appear.
func seedPathReveal(t *testing.T, pool *pgxpool.Pool, roleName string, capabilities ...string) (user, root, team, other uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	rootF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: roleName + "-root"})
	if err != nil {
		t.Fatal(err)
	}
	teamF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: roleName + "-team", ParentID: pgUUID(rootF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	otherF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: roleName + "-other", ParentID: pgUUID(rootF.ID)})
	if err != nil {
		t.Fatal(err)
	}

	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: roleName + "-user@pr", DisplayName: "PRUser"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: roleName, Capabilities: caps(capabilities...)})
	if err != nil {
		t.Fatal(err)
	}
	// Bind the management role at team ONLY (folder scope), not globally.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeFolderID: pgUUID(teamF.ID), SubjectUserID: pgUUID(u.ID),
	}); err != nil {
		t.Fatal(err)
	}
	return u.ID, rootF.ID, teamF.ID, otherF.ID
}

// assertMgmtCapPathReveal is the shared body for the three mgmt-cap tests: a user
// holding `capabilities` at the nested empty `team` folder sees the PATH to it
// (root visible, governed=false) but governs team itself (governed=true), and never
// sees the sibling `other`.
func assertMgmtCapPathReveal(t *testing.T, roleName string, capabilities ...string) {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	user, root, team, other := seedPathReveal(t, pool, roleName, capabilities...)

	// Level under root: team is revealed as governed (mgmt anchor); other is absent.
	underRoot, err := s.VisibleFoldersUnder(ctx, user, root, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(underRoot, team); !ok || !g {
		t.Fatalf("team must be visible+governed under root: present=%v governed=%v (%v)", ok, g, FolderIDsOf(underRoot))
	}
	if _, ok := governedOf(underRoot, other); ok {
		t.Fatalf("sibling other must NOT be visible under root: %v", FolderIDsOf(underRoot))
	}

	// Level at the ROOT of the tree (parent=nil): root itself is revealed as a
	// breadcrumb on the path to team — visible but NOT governed.
	atTop, err := s.VisibleFoldersUnder(ctx, user, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(atTop, root); !ok {
		t.Fatalf("root must be visible at the top level (breadcrumb to team): %v", FolderIDsOf(atTop))
	} else if g {
		t.Fatalf("root must NOT be governed (only a revealed ancestor): %v", atTop)
	}

	// Cascade from the tree root reaches team, governed=true; other never appears.
	all, err := s.VisibleFoldersUnder(ctx, user, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(all, team); !ok || !g {
		t.Fatalf("team must be reachable+governed via cascade: present=%v governed=%v (%v)", ok, g, FolderIDsOf(all))
	}
	if _, ok := governedOf(all, other); ok {
		t.Fatalf("sibling other must NEVER be visible: %v", FolderIDsOf(all))
	}
}

// TestPathRevealForRoleAdmin: a role-admin (access:role:read/create) bound at the
// nested empty team folder reveals the path to team (root ungoverned) and governs
// team; the sibling other is never visible.
func TestPathRevealForRoleAdmin(t *testing.T) {
	assertMgmtCapPathReveal(t, "pr-role-admin", "access:role:read", "access:role:create")
}

// TestPathRevealForFolderAdmin: same, via catalog:folder:read.
func TestPathRevealForFolderAdmin(t *testing.T) {
	assertMgmtCapPathReveal(t, "pr-folder-admin", "catalog:folder:read")
}

// TestPathRevealForGroupAdmin: same, via identity:group:read.
func TestPathRevealForGroupAdmin(t *testing.T) {
	assertMgmtCapPathReveal(t, "pr-group-admin", "identity:group:read")
}

// TestGovernedFalseForBreadcrumb: a user with standing (connect) access to an asset
// deep in a/b/c sees the ancestors a and b via path-reveal — visible but NEVER
// governed (they hold no management cap anywhere) — and the asset via
// VisibleAssetsUnder. Governance requires a mgmt cap, which a pure connect grant
// lacks.
func TestGovernedFalseForBreadcrumb(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	// Tree a ⊃ b ⊃ c, asset deep ∈ c.
	aF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "bc-a"})
	if err != nil {
		t.Fatal(err)
	}
	bF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "bc-b", ParentID: pgUUID(aF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	cF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "bc-c", ParentID: pgUUID(bF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	deep, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: cF.ID, Name: "bc-deep", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	// User with a standing connect binding directly on the asset (access, no mgmt).
	u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bc-user@pr", DisplayName: "BCUser"})
	if err != nil {
		t.Fatal(err)
	}
	connectRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "bc-connect", Capabilities: caps("ssh:connect")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: connectRole.ID, ScopeAssetID: pgUUID(deep.ID), SubjectUserID: pgUUID(u.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// The asset is visible under its folder c.
	assets, err := s.VisibleAssetsUnder(ctx, u.ID, cF.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := toSet(assets)[deep.ID]; !ok {
		t.Fatalf("deep asset must be visible under c: %v", assets)
	}

	// a is revealed at the top level (breadcrumb), NOT governed.
	atTop, err := s.VisibleFoldersUnder(ctx, u.ID, uuid.Nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(atTop, aF.ID); !ok {
		t.Fatalf("a must be visible at top (path to deep asset): %v", FolderIDsOf(atTop))
	} else if g {
		t.Fatalf("a must NOT be governed (connect access only): %v", atTop)
	}

	// b is revealed under a (breadcrumb), NOT governed.
	underA, err := s.VisibleFoldersUnder(ctx, u.ID, aF.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(underA, bF.ID); !ok {
		t.Fatalf("b must be visible under a (path to deep asset): %v", FolderIDsOf(underA))
	} else if g {
		t.Fatalf("b must NOT be governed (connect access only): %v", underA)
	}

	// Whole-tree cascade: none of a, b, c is governed for this connect-only user.
	all, err := s.VisibleFoldersUnder(ctx, u.ID, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []uuid.UUID{aF.ID, bF.ID, cF.ID} {
		if g, ok := governedOf(all, f); !ok {
			t.Fatalf("folder %s must be visible via cascade: %v", f, FolderIDsOf(all))
		} else if g {
			t.Fatalf("folder %s must NOT be governed for a connect-only user: %v", f, all)
		}
	}
}

// TestDeactivatedUserSeesNoFolders: after deactivation, a user who governed a nested
// folder via a management cap sees no folders at all (every anchor helper excludes a
// deactivated user, so there are no anchors and no path is revealed).
func TestDeactivatedUserSeesNoFolders(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	user, root, team, _ := seedPathReveal(t, pool, "pr-deact", "catalog:folder:read")

	// Sanity: before deactivation the user governs team and sees the path.
	before, err := s.VisibleFoldersUnder(ctx, user, root, false)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(before, team); !ok || !g {
		t.Fatalf("pre-deactivation: team must be visible+governed: %v", before)
	}

	deactivateUser(t, pool, user)

	// After deactivation: nothing at the root level, and nothing in a whole-tree cascade.
	underRoot, err := s.VisibleFoldersUnder(ctx, user, root, false)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: no folders under root", FolderIDsOf(underRoot), nil)

	all, err := s.VisibleFoldersUnder(ctx, user, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	idSet(t, "deactivated: no folders in whole-tree cascade", FolderIDsOf(all), nil)
}

// TestGlobalFolderReadGovernsWholeTree pins that the global-management short-circuit
// preserves its semantics under path-reveal: a user with a global catalog:folder:read
// sees EVERY folder at the level and governs all of them (governed=true).
func TestGlobalFolderReadGovernsWholeTree(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	q := gen.New(pool)

	// admin (from seedTree) holds catalog:folder:read globally; tree root ⊃ f1 ⊃ f2.
	admin, _, _, root, f1, f2, _, _ := seedTree(t, pool)

	// A second top-level branch with no relationship to admin's access arm, to prove
	// the global cap governs it too (not just the access-reachable path).
	otherF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "gt-other", ParentID: pgUUID(root)})
	if err != nil {
		t.Fatal(err)
	}

	// Level under root: both f1 and gt-other visible AND governed.
	underRoot, err := s.VisibleFoldersUnder(ctx, admin, root, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []uuid.UUID{f1, otherF.ID} {
		if g, ok := governedOf(underRoot, f); !ok || !g {
			t.Fatalf("global folder:read must govern %s: present=%v governed=%v (%v)", f, ok, g, FolderIDsOf(underRoot))
		}
	}

	// Whole-tree cascade: f2 (deep) also visible and governed.
	all, err := s.VisibleFoldersUnder(ctx, admin, uuid.Nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := governedOf(all, f2); !ok || !g {
		t.Fatalf("global folder:read must govern deep f2: present=%v governed=%v (%v)", ok, g, FolderIDsOf(all))
	}
}
