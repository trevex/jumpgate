package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// seedConnectCascade builds the folder-cascade visibility fixture:
//
//	folders   root ⊃ cf (the "cascade" folder)
//	asset     cbox ∈ cf, with a single SSH login "demo" (kind ca)
//	admin     scopeless (global) `**` role — sees everything, connect-visible or not
//	alice     role carrying ssh:login:demo, bound at folder cf (NOT on the asset).
//	          Connect-visible via the cascade; holds no catalog:asset:read and no
//	          asset-scoped binding.
//	carol     role carrying ssh:login:root, bound at folder cf. cbox has no `root`
//	          login, so carol entitles NO login on it → NOT connect-visible.
//	nobody    no roles at all → sees nothing.
func seedConnectCascade(t *testing.T, pool *pgxpool.Pool) (admin, alice, carol, nobody, root, cf, cbox uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	mk := func(email string) uuid.UUID {
		u, err := q.CreateUser(ctx, gen.CreateUserParams{Email: email, DisplayName: email})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	adminU := mk("cc-admin@x")
	aliceU := mk("cc-alice@x")
	carolU := mk("cc-carol@x")
	nobodyU := mk("cc-nobody@x")

	rootF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "cc-root"})
	if err != nil {
		t.Fatal(err)
	}
	cfF, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "cc-cascade", ParentID: pgUUID(rootF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	cboxA, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: cfF.ID, Name: "cc-box", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	// cbox has exactly one login: demo (kind ca needs no secret).
	if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: cboxA.ID, Login: "demo", Kind: "ca",
	}); err != nil {
		t.Fatal(err)
	}

	// admin: scopeless (global) ** role.
	adminRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "cc-admin-role", Capabilities: caps("**")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: adminRole.ID, SubjectUserID: pgUUID(adminU),
	}); err != nil {
		t.Fatal(err)
	}

	// alice: ssh:login:demo bound at the folder cf (folder cascade, no asset binding).
	demoRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "cc-demo-role", Capabilities: caps("ssh:login:demo")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: demoRole.ID, ScopeFolderID: pgUUID(cfF.ID), SubjectUserID: pgUUID(aliceU),
	}); err != nil {
		t.Fatal(err)
	}

	// carol: ssh:login:root bound at cf — entitles no login on cbox (only demo exists).
	rootRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "cc-root-role", Capabilities: caps("ssh:login:root")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: rootRole.ID, ScopeFolderID: pgUUID(cfF.ID), SubjectUserID: pgUUID(carolU),
	}); err != nil {
		t.Fatal(err)
	}

	return adminU, aliceU, carolU, nobodyU, rootF.ID, cfF.ID, cboxA.ID
}

// alice reaches cbox ONLY via the folder-scoped ssh:login:demo binding: the asset
// is in VisibleAssetsUnder and its ancestor folder cf is in VisibleFoldersUnder.
func TestConnectCascadeVisible(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	_, alice, _, _, root, cf, cbox := seedConnectCascade(t, pool)

	assets, err := s.VisibleAssetsUnder(ctx, alice, cf, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := toSet(assets)[cbox]; !ok {
		t.Fatalf("alice: cbox not connect-visible under cf: %v", assets)
	}

	// The cascade folder must surface so the browse path down to cbox exists. Query
	// the level under root (cf is a child of root). cf is visible because it is an
	// ancestor-or-self of the anchor cbox's folder (path-reveal).
	vf, err := s.VisibleFoldersUnder(ctx, alice, root, false)
	if err != nil {
		t.Fatal(err)
	}
	folders := FolderIDsOf(vf)
	if _, ok := toSet(folders)[cf]; !ok {
		t.Fatalf("alice: cf ancestor folder not visible under root: %v", folders)
	}
}

// The ** admin still sees ALL assets and folders (regression — ** visibility preserved).
func TestConnectCascadeAdminSeesAll(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	admin, _, _, _, root, cf, cbox := seedConnectCascade(t, pool)

	assets, err := s.VisibleAssetsUnder(ctx, admin, cf, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := toSet(assets)[cbox]; !ok {
		t.Fatalf("admin(**): cbox not visible: %v", assets)
	}
	vf, err := s.VisibleFoldersUnder(ctx, admin, root, false)
	if err != nil {
		t.Fatal(err)
	}
	folders := FolderIDsOf(vf)
	if _, ok := toSet(folders)[cf]; !ok {
		t.Fatalf("admin(**): cf not visible: %v", folders)
	}
}

// carol holds ssh:login:root at cf but cbox has only a `demo` login, so she
// entitles NO login on it → NOT visible (existence-hiding preserved).
func TestConnectCascadeNoEntitledLogin(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	_, _, carol, _, root, cf, cbox := seedConnectCascade(t, pool)

	assets, err := s.VisibleAssetsUnder(ctx, carol, cf, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := toSet(assets)[cbox]; ok {
		t.Fatalf("carol: cbox unexpectedly visible with no entitled login: %v", assets)
	}
	// With no visible asset in the subtree and no other anchor, the cascade folder
	// must stay hidden too (carol has no path-reveal anchor at/under cf).
	vf, err := s.VisibleFoldersUnder(ctx, carol, root, false)
	if err != nil {
		t.Fatal(err)
	}
	folders := FolderIDsOf(vf)
	if _, ok := toSet(folders)[cf]; ok {
		t.Fatalf("carol: cf unexpectedly visible: %v", folders)
	}
}

// A user with no roles sees nothing (regression).
func TestConnectCascadeNobody(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := NewSQLAuthorizer(pool).(*sqlAuthorizer)
	_, _, _, nobody, root, cf, _ := seedConnectCascade(t, pool)

	assets, err := s.VisibleAssetsUnder(ctx, nobody, cf, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 0 {
		t.Fatalf("nobody: expected no assets, got %v", assets)
	}
	vf, err := s.VisibleFoldersUnder(ctx, nobody, root, false)
	if err != nil {
		t.Fatal(err)
	}
	folders := FolderIDsOf(vf)
	if len(folders) != 0 {
		t.Fatalf("nobody: expected no folders, got %v", folders)
	}
}
