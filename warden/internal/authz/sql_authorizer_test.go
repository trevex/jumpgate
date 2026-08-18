package authz

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func caps(xs ...string) []byte { b, _ := json.Marshal(xs); return b }

func newPool(t *testing.T) *pgxpool.Pool {
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

// seed builds:
//
//	alice ∈ sre ∈ platform
//	folder prod ⊃ prod-db; asset pgprod ∈ prod-db; asset apiprod ∈ prod
//	folder staging; asset pgstaging ∈ staging
//	folder secret; asset topsecret ∈ secret
//	role operator(caps connect,read,write); role viewer(caps read)
//	binding: platform -> operator STANDING on folder prod  (⇒ pgprod, apiprod active)
//	binding: sre -> viewer REQUESTABLE on asset pgstaging   (⇒ pgstaging requestable-only)
//	(topsecret: no binding ⇒ invisible to alice)
func seed(t *testing.T, pool *pgxpool.Pool) (alice, pgprod, apiprod, pgstaging, topsecret, operatorRole, viewerRole uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	au, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	sre, err := q.CreateGroup(ctx, "sre")
	if err != nil {
		t.Fatal(err)
	}
	platform, err := q.CreateGroup(ctx, "platform")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: sre.ID, MemberUserID: pgUUID(au.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: platform.ID, MemberGroupID: pgUUID(sre.ID)}); err != nil {
		t.Fatal(err)
	}

	prod, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	proddb, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod-db", ParentID: pgUUID(prod.ID)})
	if err != nil {
		t.Fatal(err)
	}
	staging, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	mkAsset := func(folder uuid.UUID, name string) uuid.UUID {
		a, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder, Name: name, Labels: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	pgprod = mkAsset(proddb.ID, "pg-prod")
	apiprod = mkAsset(prod.ID, "api-prod")
	pgstaging = mkAsset(staging.ID, "pg-staging")
	topsecret = mkAsset(secret.ID, "top-secret")

	op, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "operator", ResourceType: "asset", Capabilities: caps("connect", "read", "write")})
	if err != nil {
		t.Fatal(err)
	}
	vw, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "viewer", ResourceType: "asset", Capabilities: caps("read")})
	if err != nil {
		t.Fatal(err)
	}

	// operator cascades down folders via an explicit parent self-rule.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: op.ID, SourceRoleID: op.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}

	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: op.ID, Kind: "standing", ScopeFolderID: pgUUID(prod.ID), SubjectGroupID: pgUUID(platform.ID),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: vw.ID, Kind: "requestable", ScopeAssetID: pgUUID(pgstaging), SubjectGroupID: pgUUID(sre.ID),
	}); err != nil {
		t.Fatal(err)
	}

	return au.ID, pgprod, apiprod, pgstaging, topsecret, op.ID, vw.ID
}

func TestVisibleAssetsTiers(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, apiprod, pgstaging, topsecret, _, _ := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	vis, err := a.VisibleAssets(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}

	got := map[uuid.UUID]bool{}
	for _, v := range vis {
		got[v.AssetID] = v.Active
	}
	if active, ok := got[pgprod]; !ok || !active {
		t.Fatalf("pgprod: want visible+active, got ok=%v active=%v", ok, active)
	}
	if active, ok := got[apiprod]; !ok || !active {
		t.Fatalf("apiprod: want visible+active, got ok=%v active=%v", ok, active)
	}
	if active, ok := got[pgstaging]; !ok || active {
		t.Fatalf("pgstaging: want visible+requestable, got ok=%v active=%v", ok, active)
	}
	if _, ok := got[topsecret]; ok {
		t.Fatalf("topsecret must be invisible")
	}
}

func TestCheckCapability(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, _, pgstaging, topsecret, _, _ := seed(t, pool)
	a := NewSQLAuthorizer(pool)
	ctx := context.Background()

	if ok, err := a.Check(ctx, alice, pgprod, "write"); err != nil || !ok {
		t.Fatalf("Check(write, pgprod) = %v, %v; want true", ok, err)
	}
	if ok, err := a.Check(ctx, alice, pgprod, "admin"); err != nil || ok {
		t.Fatalf("Check(admin, pgprod) = %v, %v; want false", ok, err)
	}
	if ok, err := a.Check(ctx, alice, pgstaging, "read"); err != nil || ok {
		t.Fatalf("Check(read, pgstaging) = %v, %v; want false (requestable != active)", ok, err)
	}
	if ok, err := a.Check(ctx, alice, topsecret, "read"); err != nil || ok {
		t.Fatalf("Check(read, topsecret) = %v, %v; want false", ok, err)
	}
}

func TestThreeLevelFolderInheritance(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	alice, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, "eng")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(alice.ID)}); err != nil {
		t.Fatal(err)
	}

	gp, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "gp"})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "parent", ParentID: pgUUID(gp.ID)})
	if err != nil {
		t.Fatal(err)
	}
	child, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "child", ParentID: pgUUID(parent.ID)})
	if err != nil {
		t.Fatal(err)
	}

	deepAsset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: child.ID, Name: "deep", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "op3", ResourceType: "asset", Capabilities: caps("read")})
	if err != nil {
		t.Fatal(err)
	}
	// op3 cascades down folders via an explicit parent self-rule.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: role.ID, SourceRoleID: role.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// standing binding on the GRANDPARENT folder
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, Kind: "standing", ScopeFolderID: pgUUID(gp.ID), SubjectGroupID: pgUUID(grp.ID),
	}); err != nil {
		t.Fatal(err)
	}

	a := NewSQLAuthorizer(pool)
	if ok, err := a.Check(ctx, alice.ID, deepAsset.ID, "read"); err != nil || !ok {
		t.Fatalf("Check(read, deepAsset via 3-level inheritance) = %v, %v; want true", ok, err)
	}
	vis, err := a.VisibleAssets(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range vis {
		if v.AssetID == deepAsset.ID {
			found = true
			if !v.Active {
				t.Fatal("deepAsset should be active")
			}
		}
	}
	if !found {
		t.Fatal("deepAsset should be visible via 3-level folder inheritance")
	}
}

func TestRolesOnAsset(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, _, pgstaging, _, operatorRole, viewerRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)
	ctx := context.Background()

	r, err := a.RolesOnAsset(ctx, alice, pgprod)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Active) != 1 || r.Active[0] != operatorRole {
		t.Fatalf("pgprod active roles = %v, want [operator]", r.Active)
	}
	if len(r.Requestable) != 0 {
		t.Fatalf("pgprod requestable = %v, want none", r.Requestable)
	}

	r2, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Active) != 0 {
		t.Fatalf("pgstaging active = %v, want none", r2.Active)
	}
	if len(r2.Requestable) != 1 || r2.Requestable[0] != viewerRole {
		t.Fatalf("pgstaging requestable = %v, want [viewer]", r2.Requestable)
	}
}
