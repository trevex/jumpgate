package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestCovers pins the pattern-vs-pattern subsumption semantics of Covers/covers1.
func TestCovers(t *testing.T) {
	cases := []struct {
		name   string
		held   []string
		target string
		want   bool
	}{
		{"dstar covers anything", []string{"**"}, "identity:user:read", true},
		{"dstar covers single", []string{"**"}, "catalog", true},

		{"scoped dstar covers concrete tail", []string{"catalog:**"}, "catalog:asset:create", true},
		{"scoped dstar covers star tail", []string{"catalog:**"}, "catalog:asset:*", true},
		{"scoped dstar rejects other scope", []string{"catalog:**"}, "identity:user:read", false},

		{"single star covers one existing seg", []string{"catalog:*"}, "catalog:asset", true},
		{"single star does not cover dstar", []string{"catalog:*"}, "catalog:**", false},
		{"single star does not cover extra seg", []string{"catalog:*"}, "catalog:asset:create", false},

		{"login star covers concrete", []string{"ssh:login:*"}, "ssh:login:deploy", true},

		{"exact match", []string{"catalog:asset:create"}, "catalog:asset:create", true},
		{"concrete does not cover sibling", []string{"catalog:asset:read"}, "catalog:asset:create", false},

		{"multi-held covers via dstar", []string{"catalog:asset:*", "access:**"}, "access:role:create", true},

		{"nil covers nothing", nil, "catalog:asset:create", false},
		{"empty covers nothing", []string{}, "anything", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Covers(tc.held, tc.target); got != tc.want {
				t.Fatalf("Covers(%v, %q) = %v, want %v", tc.held, tc.target, got, tc.want)
			}
		})
	}
}

// insertGlobalBinding inserts a scopeless (global) standing role_binding for a
// user directly — the sqlc CreateRoleBinding path could set both scopes NULL too,
// but writing it explicitly documents intent and is independent of null handling.
func insertGlobalBinding(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, roleID, userID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO role_bindings (role_id, scope_folder_id, scope_asset_id, subject_user_id)
		 VALUES ($1, NULL, NULL, $2)`, roleID, userID); err != nil {
		t.Fatalf("insert global binding: %v", err)
	}
}

// TestCapabilitiesOnScope pins the management-scope capability resolution over
// real Postgres: a scopeless (global) standing binding applies at every scope; a
// folder binding applies at that folder and its child assets but not siblings or
// globally; a deactivated user holds nothing anywhere.
func TestCapabilitiesOnScope(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mgr := createRoleWithCaps(t, ctx, q, "mgr", pgtype.UUID{}, caps("catalog:asset:create"))

	folderF, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "scope-f"})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "scope-sibling"})
	if err != nil {
		t.Fatal(err)
	}
	subFolder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "scope-sub", ParentID: pgUUID(folderF.ID)})
	if err != nil {
		t.Fatal(err)
	}
	childAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folderF.ID, Name: "scope-child", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	// NO role_grants(mgr,mgr,parent) self-edge: management scoping cascades
	// STRUCTURALLY down the folder tree (via the folder ancestor walk in
	// CapabilitiesOnScope), not via the opt-in data-plane parent inheritance.

	a := NewSQLAuthorizer(pool).(*sqlAuthorizer)

	// --- scopeless global standing binding ---
	gUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "scope-global@x", DisplayName: "G"})
	if err != nil {
		t.Fatal(err)
	}
	insertGlobalBinding(t, pool, mgr.ID, gUser.ID)

	for _, sc := range []struct {
		name  string
		scope Scope
	}{
		{"global", GlobalScope()},
		{"folder", FolderScope(folderF.ID)},
		{"asset", AssetScope(childAsset.ID)},
	} {
		capsSet, err := a.CapabilitiesOnScope(ctx, gUser.ID, sc.scope)
		if err != nil {
			t.Fatalf("global user CapabilitiesOnScope(%s): %v", sc.name, err)
		}
		if !capsSet.Allows("catalog:asset:create") {
			t.Fatalf("global user must hold catalog:asset:create at %s scope; caps=%v", sc.name, capsSet)
		}
	}

	// --- folder-scoped standing binding on folder F ---
	fUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "scope-folder@x", DisplayName: "F"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: mgr.ID, ScopeFolderID: pgUUID(folderF.ID), SubjectUserID: pgUUID(fUser.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// true at folder F
	if c, err := a.CapabilitiesOnScope(ctx, fUser.ID, FolderScope(folderF.ID)); err != nil || !c.Allows("catalog:asset:create") {
		t.Fatalf("folder user at FolderScope(F): allows=%v err=%v; want true", c.Allows("catalog:asset:create"), err)
	}
	// true at sub-folder of F (structural cascade, no parent self-grant)
	if c, err := a.CapabilitiesOnScope(ctx, fUser.ID, FolderScope(subFolder.ID)); err != nil || !c.Allows("catalog:asset:create") {
		t.Fatalf("folder user at FolderScope(sub): allows=%v err=%v; want true", c.Allows("catalog:asset:create"), err)
	}
	// true at child asset of F (structural cascade, no parent self-grant)
	if c, err := a.CapabilitiesOnScope(ctx, fUser.ID, AssetScope(childAsset.ID)); err != nil || !c.Allows("catalog:asset:create") {
		t.Fatalf("folder user at AssetScope(child): allows=%v err=%v; want true", c.Allows("catalog:asset:create"), err)
	}
	// false at sibling folder
	if c, err := a.CapabilitiesOnScope(ctx, fUser.ID, FolderScope(sibling.ID)); err != nil || c.Allows("catalog:asset:create") {
		t.Fatalf("folder user at FolderScope(sibling): allows=%v err=%v; want false", c.Allows("catalog:asset:create"), err)
	}
	// false at global scope
	if c, err := a.CapabilitiesOnScope(ctx, fUser.ID, GlobalScope()); err != nil || c.Allows("catalog:asset:create") {
		t.Fatalf("folder user at GlobalScope: allows=%v err=%v; want false", c.Allows("catalog:asset:create"), err)
	}

	// --- deactivated user with a global binding holds nothing anywhere ---
	dUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "scope-deactivated@x", DisplayName: "D"})
	if err != nil {
		t.Fatal(err)
	}
	insertGlobalBinding(t, pool, mgr.ID, dUser.ID)
	if _, err := pool.Exec(ctx, `UPDATE users SET deactivated_at = now() WHERE id = $1`, dUser.ID); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	for _, sc := range []struct {
		name  string
		scope Scope
	}{
		{"global", GlobalScope()},
		{"folder", FolderScope(folderF.ID)},
		{"asset", AssetScope(childAsset.ID)},
	} {
		c, err := a.CapabilitiesOnScope(ctx, dUser.ID, sc.scope)
		if err != nil {
			t.Fatalf("deactivated user CapabilitiesOnScope(%s): %v", sc.name, err)
		}
		if c.Allows("catalog:asset:create") {
			t.Fatalf("deactivated user must hold nothing at %s scope; caps=%v", sc.name, c)
		}
	}
}
