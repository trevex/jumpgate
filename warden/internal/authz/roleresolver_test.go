package authz_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func newResolverPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestHoldsRole(t *testing.T) {
	pool := newResolverPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	// ── roles ────────────────────────────────────────────────────────────────
	caps := []byte("[]")
	mkRole := func(name string) uuid.UUID {
		r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name, Capabilities: caps})
		if err != nil {
			t.Fatalf("CreateRole(%s): %v", name, err)
		}
		return r.ID
	}
	owner := mkRole("owner")
	editor := mkRole("editor")
	clusterEditor := mkRole("cluster_editor")
	admin := mkRole("admin")

	// ── role_grants (rewrite rules) ───────────────────────────────────────────
	mkGrant := func(roleID, sourceID uuid.UUID, via string) {
		if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{
			RoleID: roleID, SourceRoleID: sourceID, Via: via,
		}); err != nil {
			t.Fatalf("CreateRoleGrant: %v", err)
		}
	}
	// editor ← owner via same_object
	mkGrant(editor, owner, "same_object")
	// editor ← editor via parent  (cascades down)
	mkGrant(editor, editor, "parent")
	// cluster_editor ← admin via same_object
	mkGrant(clusterEditor, admin, "same_object")
	// cluster_editor ← editor via parent
	mkGrant(clusterEditor, editor, "parent")

	// ── folders: prod (root), proddb (child of prod) ─────────────────────────
	prod, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder prod: %v", err)
	}
	proddb, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "proddb", ParentID: pg(prod.ID)})
	if err != nil {
		t.Fatalf("CreateFolder proddb: %v", err)
	}

	// ── asset pg in proddb ────────────────────────────────────────────────────
	pgAsset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: proddb.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset pg: %v", err)
	}

	// ── users ─────────────────────────────────────────────────────────────────
	alice, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	bob, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}

	// ── group sre, alice ∈ sre ────────────────────────────────────────────────
	sre, err := q.CreateGroup(ctx, "sre")
	if err != nil {
		t.Fatalf("CreateGroup sre: %v", err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: sre.ID, MemberUserID: pg(alice.ID)}); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}

	// ── binding: sre → owner STANDING on folder prod ─────────────────────────
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:         owner,
		ScopeFolderID:  pg(prod.ID),
		SubjectGroupID: pg(sre.ID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	r := authz.NewRoleResolver(pool)

	// ── core assertions ───────────────────────────────────────────────────────
	check := func(name string, wantOK bool, userID, roleID uuid.UUID, objectKind string, objectID uuid.UUID) {
		t.Helper()
		got, err := r.HoldsRole(ctx, userID, roleID, objectKind, objectID)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if got != wantOK {
			t.Errorf("%s: HoldsRole = %v, want %v", name, got, wantOK)
		}
	}

	// direct via group sre
	check("alice owner folder/prod", true, alice.ID, owner, "folder", prod.ID)
	// editor ← owner same_object
	check("alice editor folder/prod", true, alice.ID, editor, "folder", prod.ID)
	// editor ← editor parent (from prod)
	check("alice editor folder/proddb", true, alice.ID, editor, "folder", proddb.ID)
	// cluster_editor ← editor parent → editor@proddb (via editor←editor parent from prod ← owner@prod)
	check("alice cluster_editor asset/pg", true, alice.ID, clusterEditor, "asset", pgAsset.ID)
	// bob has no binding at all
	check("bob cluster_editor asset/pg false", false, bob.ID, clusterEditor, "asset", pgAsset.ID)
	// no path to admin
	check("alice admin asset/pg false", false, alice.ID, admin, "asset", pgAsset.ID)

	// ── cycle safety ──────────────────────────────────────────────────────────
	cyca := mkRole("cyca")
	cycb := mkRole("cycb")
	mkGrant(cyca, cycb, "same_object") // cyca ← cycb
	mkGrant(cycb, cyca, "same_object") // cycb ← cyca

	// Must return false AND must not hang (timeout guard).
	done := make(chan struct{})
	var cycOK bool
	var cycErr error
	go func() {
		defer close(done)
		cycOK, cycErr = r.HoldsRole(ctx, bob.ID, cyca, "asset", pgAsset.ID)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cycle test: HoldsRole did not terminate within 10s (infinite loop?)")
	}
	if cycErr != nil {
		t.Fatalf("cycle test: unexpected error: %v", cycErr)
	}
	if cycOK {
		t.Errorf("cycle test: HoldsRole(bob, cyca, asset, pg) = true, want false")
	}

	// ── direct on asset ───────────────────────────────────────────────────────
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        admin,
		ScopeAssetID:  pg(pgAsset.ID),
		SubjectUserID: pg(bob.ID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding bob/admin/asset: %v", err)
	}
	check("bob admin asset/pg direct", true, bob.ID, admin, "asset", pgAsset.ID)

	// ── nested-group membership ───────────────────────────────────────────────
	// alice ∈ teamA ∈ sre. alice only holds owner@prod through the sre binding, so
	// the extra nesting layer must still resolve.
	teamA, err := q.CreateGroup(ctx, "teamA")
	if err != nil {
		t.Fatalf("CreateGroup teamA: %v", err)
	}
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: sre.ID, MemberGroupID: pg(teamA.ID)}); err != nil {
		t.Fatalf("AddGroupToGroup teamA→sre: %v", err)
	}
	// Move alice's membership one level deeper: alice ∈ teamA (teamA ∈ sre).
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: teamA.ID, MemberUserID: pg(alice.ID)}); err != nil {
		t.Fatalf("AddUserToGroup alice→teamA: %v", err)
	}
	check("alice owner folder/prod via nested teamA∈sre", true, alice.ID, owner, "folder", prod.ID)
}
