package authz

import (
	"context"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

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
