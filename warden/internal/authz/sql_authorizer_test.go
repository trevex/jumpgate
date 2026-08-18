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

// seed builds (access-model v2: role_bindings are standing-only; the Requestable
// tier comes from request_policy eligibility, never from bindings):
//
//	alice ∈ sre ∈ platform
//	folder prod ⊃ prod-db; asset pgprod ∈ prod-db; asset apiprod ∈ prod
//	folder staging; asset pgstaging ∈ staging
//	folder secret; asset topsecret ∈ secret
//	role operator(caps connect,read,write); role viewer(caps read); role dba(caps admin)
//	operator + viewer cascade down folders via `parent` self-rules.
//	binding: platform -> operator STANDING on folder prod    (⇒ pgprod, apiprod active)
//	binding: sre      -> viewer   STANDING on folder staging (⇒ alice holds viewer on pgstaging via cascade)
//	request_policy(dba, scope_asset=pgstaging, requester_role=viewer, approvals=1)
//	  ⇒ pgstaging Requestable-for-dba to alice (holds viewer requester role), NOT active.
//	(topsecret: no binding, no policy ⇒ invisible to alice)
func seed(t *testing.T, pool *pgxpool.Pool) (alice, pgprod, apiprod, pgstaging, topsecret, operatorRole, viewerRole, dbaRole uuid.UUID) {
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

	op, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "operator", ResourceType: "asset", Capabilities: caps("ssh:connect", "db:read", "db:write")})
	if err != nil {
		t.Fatal(err)
	}
	vw, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "viewer", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	dba, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "dba", ResourceType: "asset", Capabilities: caps("db:admin")})
	if err != nil {
		t.Fatal(err)
	}

	// operator + viewer cascade down folders via explicit parent self-rules.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: op.ID, SourceRoleID: op.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: vw.ID, SourceRoleID: vw.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}

	// STANDING: platform -> operator on prod (⇒ pgprod, apiprod active for alice).
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: op.ID, ScopeFolderID: pgUUID(prod.ID), SubjectGroupID: pgUUID(platform.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// STANDING: sre -> viewer on staging (⇒ alice holds viewer on pgstaging via cascade).
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: vw.ID, ScopeFolderID: pgUUID(staging.ID), SubjectGroupID: pgUUID(sre.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// request_policy: dba requestable on pgstaging, requester_role=viewer.
	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: dba.ID, ScopeAssetID: pgUUID(pgstaging), RequiredApprovals: 1, RequesterRoleID: pgUUID(vw.ID),
	}); err != nil {
		t.Fatal(err)
	}

	return au.ID, pgprod, apiprod, pgstaging, topsecret, op.ID, vw.ID, dba.ID
}

func TestVisibleAssetsTiers(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, apiprod, pgstaging, topsecret, _, viewerRole, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	vis, err := a.VisibleAssets(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}

	type asset struct {
		active bool
		roles  map[uuid.UUID]bool
	}
	got := map[uuid.UUID]asset{}
	for _, v := range vis {
		roles := map[uuid.UUID]bool{}
		for _, rid := range v.RoleIDs {
			roles[rid] = true
		}
		got[v.AssetID] = asset{active: v.Active, roles: roles}
	}
	if a, ok := got[pgprod]; !ok || !a.active {
		t.Fatalf("pgprod: want visible+active, got ok=%v active=%v", ok, a.active)
	}
	if a, ok := got[apiprod]; !ok || !a.active {
		t.Fatalf("apiprod: want visible+active, got ok=%v active=%v", ok, a.active)
	}
	// pgstaging: alice holds `viewer` Active (sre→staging standing + parent cascade),
	// so the asset is Active. `dba` is Requestable there (policy names viewer as the
	// requester_role, which alice holds) — so RoleIDs must include BOTH.
	psa, ok := got[pgstaging]
	if !ok {
		t.Fatalf("pgstaging must be visible")
	}
	if !psa.active {
		t.Fatalf("pgstaging: want Active=true (viewer held Active via cascade), got false")
	}
	if !psa.roles[viewerRole] || !psa.roles[dbaRole] {
		t.Fatalf("pgstaging RoleIDs = %v, want to include viewer(%v)+dba(%v)", psa.roles, viewerRole, dbaRole)
	}
	if _, ok := got[topsecret]; ok {
		t.Fatalf("topsecret must be invisible")
	}
}

// TestRequestableViaExplicitSubject pins the Requestable-only (Active=false) path
// through an explicit kind='requester' subject with NO prerequisite standing role:
// a policy (breakglass on some asset, no requester_role) names group `contractors`
// as a requester subject; member carol — who holds NO standing role on that asset
// — sees the asset Requestable-only (visible, Active=false, dba/breakglass in
// .Requestable, .Active empty). A non-member/non-holder (bob) sees it invisible.
func TestRequestableViaExplicitSubject(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	carol, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "carol@x", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	// carol ∈ subteam ∈ contractors (nested group, group-aware subject matching).
	contractors, err := q.CreateGroup(ctx, "contractors")
	if err != nil {
		t.Fatal(err)
	}
	subteam, err := q.CreateGroup(ctx, "subteam")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: subteam.ID, MemberUserID: pgUUID(carol.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: contractors.ID, MemberGroupID: pgUUID(subteam.ID)}); err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "bg-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "bg-asset", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	breakglass, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "breakglass", ResourceType: "asset", Capabilities: caps("db:admin")})
	if err != nil {
		t.Fatal(err)
	}
	// Policy with NO requester_role — eligibility is ONLY via explicit subjects.
	pol, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: breakglass.ID, ScopeAssetID: pgUUID(asset.ID), RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, gen.AddPolicySubjectParams{
		PolicyID: pol.ID, Kind: "requester", SubjectGroupID: pgUUID(contractors.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// carol: Requestable-only (Active=false), .Requestable == [breakglass], .Active empty.
	vis, err := a.VisibleAssets(ctx, carol.ID)
	if err != nil {
		t.Fatal(err)
	}
	var found *AssetVisibility
	for i := range vis {
		if vis[i].AssetID == asset.ID {
			found = &vis[i]
		}
	}
	if found == nil {
		t.Fatal("carol: bg-asset must be visible (Requestable via explicit subject)")
	}
	if found.Active {
		t.Fatal("carol: bg-asset must be Active=false (no standing role)")
	}
	roles, err := a.RolesOnAsset(ctx, carol.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles.Active) != 0 {
		t.Fatalf("carol RolesOnAsset.Active = %v, want none", roles.Active)
	}
	if len(roles.Requestable) != 1 || roles.Requestable[0] != breakglass.ID {
		t.Fatalf("carol RolesOnAsset.Requestable = %v, want [breakglass]", roles.Requestable)
	}

	// bob: not a subject, holds nothing → invisible, empty roles.
	visB, err := a.VisibleAssets(ctx, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range visB {
		if v.AssetID == asset.ID {
			t.Fatal("bob: bg-asset must be invisible")
		}
	}
	rolesB, err := a.RolesOnAsset(ctx, bob.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rolesB.Active) != 0 || len(rolesB.Requestable) != 0 {
		t.Fatalf("bob RolesOnAsset = %+v, want empty", rolesB)
	}
}

// TestRequestableIneligibleNoRequesterMatch pins that a user who does NOT hold the
// policy's requester_role and is NOT a requester subject gets NO requestable role,
// and the asset stays invisible — i.e. a NULL/unmatched requester never means
// "anyone". bob is such a user against the seed's dba@pgstaging policy.
func TestRequestableIneligibleNoRequesterMatch(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	_, _, _, pgstaging, _, _, _, _ := seed(t, pool)
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	bob, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob-ineligible@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	vis, err := a.VisibleAssets(ctx, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vis {
		if v.AssetID == pgstaging {
			t.Fatalf("bob: pgstaging must be invisible (holds no viewer, not a requester subject); got %+v", v)
		}
	}
	roles, err := a.RolesOnAsset(ctx, bob.ID, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles.Active) != 0 || len(roles.Requestable) != 0 {
		t.Fatalf("bob RolesOnAsset(pgstaging) = %+v, want empty", roles)
	}
}

// TestActiveExcludesRequestable pins that a role the user already holds Active
// (standing) on an asset is NEVER also reported Requestable there, even if a
// request_policy would otherwise make it eligible. Give alice a standing `dba`
// binding on pgstaging: dba must move to .Active and vanish from .Requestable.
func TestActiveExcludesRequestable(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	// Pre-condition: dba is Requestable (not Active) for alice on pgstaging.
	pre, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre.Requestable) != 1 || pre.Requestable[0] != dbaRole {
		t.Fatalf("pre: pgstaging requestable = %v, want [dba]", pre.Requestable)
	}

	// Grant alice a standing dba binding directly on pgstaging.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: dbaRole, ScopeAssetID: pgUUID(pgstaging), SubjectUserID: pgUUID(alice),
	}); err != nil {
		t.Fatal(err)
	}

	post, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	activeHasDBA := false
	for _, r := range post.Active {
		if r == dbaRole {
			activeHasDBA = true
		}
	}
	if !activeHasDBA {
		t.Fatalf("post: dba must be Active, got .Active=%v", post.Active)
	}
	for _, r := range post.Requestable {
		if r == dbaRole {
			t.Fatalf("post: dba must NOT be Requestable once Active; got .Requestable=%v", post.Requestable)
		}
	}
}

func TestCheckCapability(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, _, pgstaging, topsecret, _, _, _ := seed(t, pool)
	a := NewSQLAuthorizer(pool)
	ctx := context.Background()

	if ok, err := a.Check(ctx, alice, pgprod, "db:write"); err != nil || !ok {
		t.Fatalf("Check(db:write, pgprod) = %v, %v; want true", ok, err)
	}
	if ok, err := a.Check(ctx, alice, pgprod, "db:admin"); err != nil || ok {
		t.Fatalf("Check(db:admin, pgprod) = %v, %v; want false", ok, err)
	}
	// alice holds `viewer` Active on pgstaging (sre→staging standing + cascade),
	// so viewer's db:read is granted there.
	if ok, err := a.Check(ctx, alice, pgstaging, "db:read"); err != nil || !ok {
		t.Fatalf("Check(db:read, pgstaging) = %v, %v; want true (viewer active via cascade)", ok, err)
	}
	// dba (db:admin) is only Requestable on pgstaging — requestable != active, so
	// its capability must NOT be granted.
	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || ok {
		t.Fatalf("Check(db:admin, pgstaging) = %v, %v; want false (dba requestable != active)", ok, err)
	}
	if ok, err := a.Check(ctx, alice, topsecret, "db:read"); err != nil || ok {
		t.Fatalf("Check(db:read, topsecret) = %v, %v; want false", ok, err)
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

	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "op3", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	// op3 cascades down folders via an explicit parent self-rule.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: role.ID, SourceRoleID: role.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// standing binding on the GRANDPARENT folder
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeFolderID: pgUUID(gp.ID), SubjectGroupID: pgUUID(grp.ID),
	}); err != nil {
		t.Fatal(err)
	}

	a := NewSQLAuthorizer(pool)
	if ok, err := a.Check(ctx, alice.ID, deepAsset.ID, "db:read"); err != nil || !ok {
		t.Fatalf("Check(db:read, deepAsset via 3-level inheritance) = %v, %v; want true", ok, err)
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

// TestCheckExplicitFolderCascade pins the security-critical invariant that
// heldCTE's forward closure honors ONLY the explicit role_grants graph: a
// STANDING binding on a folder does NOT reach a descendant asset unless an
// explicit `parent` self-rule exists. This asserts the negative first, then adds
// the rule and asserts the flip — a regression reintroducing an implicit folder
// walk in heldCTE would make the negative assertion fail.
func TestCheckExplicitFolderCascade(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "cascade@x", DisplayName: "Cascade"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, "cascade-grp")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}

	parent, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "cascade-parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "cascade-child", ParentID: pgUUID(parent.ID)})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: child.ID, Name: "cascade-asset", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	op, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "cascade-op", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	// STANDING binding of op to the group on the PARENT folder. No role_grant yet.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: op.ID, ScopeFolderID: pgUUID(parent.ID), SubjectGroupID: pgUUID(grp.ID),
	}); err != nil {
		t.Fatal(err)
	}

	a := NewSQLAuthorizer(pool)

	// Negative: without an explicit `parent` rule the folder binding must NOT
	// reach the descendant asset.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:read"); err != nil || ok {
		t.Fatalf("Check(db:read, asset) before grant = %v, %v; want false (no implicit folder walk)", ok, err)
	}
	// Pin the visibility path too: asset must not be Active.
	vis, err := a.VisibleAssets(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vis {
		if v.AssetID == asset.ID && v.Active {
			t.Fatal("asset must NOT be active before grant")
		}
	}
	roles, err := a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles.Active) != 0 {
		t.Fatalf("RolesOnAsset.Active before grant = %v, want none", roles.Active)
	}

	// Add the explicit op ⊇ op via parent rule.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: op.ID, SourceRoleID: op.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}

	// Positive: the flip proves heldCTE honors the explicit-only cascade.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:read"); err != nil || !ok {
		t.Fatalf("Check(db:read, asset) after grant = %v, %v; want true", ok, err)
	}
	vis2, err := a.VisibleAssets(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	activeNow := false
	for _, v := range vis2 {
		if v.AssetID == asset.ID {
			activeNow = v.Active
		}
	}
	if !activeNow {
		t.Fatal("asset must be active after grant")
	}
	roles2, err := a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles2.Active) != 1 || roles2.Active[0] != op.ID {
		t.Fatalf("RolesOnAsset.Active after grant = %v, want [op]", roles2.Active)
	}
}

// TestCheckSameObjectComposition pins that a `same_object` rewrite confers a
// source role's capabilities on the SAME object: holding `super` on an asset,
// with rule (super ⊇ base same_object), yields base's capability there. This
// proves Check's held ⋈ roles.capabilities join picks up rewrite-conferred
// roles, not just the directly-bound one.
func TestCheckSameObjectComposition(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "compose@x", DisplayName: "Compose"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, "compose-grp")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "compose-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "compose-asset", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	base, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "compose-base", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	super, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "compose-super", ResourceType: "asset", Capabilities: caps("db:write")})
	if err != nil {
		t.Fatal(err)
	}
	// Rule: holding super on O confers base on O. In role_grants terms the goal
	// `base` reduces to source `super` (role_id=base, source_role_id=super), so the
	// forward closure adds base whenever super is held. (This is the (base ⊇ super)
	// direction — "base is conferred by super" — matching the goal-expansion engine
	// where WHERE rg.source_role_id = h.role_id SELECT rg.role_id.)
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: base.ID, SourceRoleID: super.ID, Via: "same_object"}); err != nil {
		t.Fatal(err)
	}
	// STANDING binding of super to the group on the asset.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: super.ID, ScopeAssetID: pgUUID(asset.ID), SubjectGroupID: pgUUID(grp.ID),
	}); err != nil {
		t.Fatal(err)
	}

	a := NewSQLAuthorizer(pool)

	// super's own capability holds directly.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:write"); err != nil || !ok {
		t.Fatalf("Check(db:write, asset) = %v, %v; want true (super's own cap)", ok, err)
	}
	// read comes from base, reachable via the same_object rewrite from super.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:read"); err != nil || !ok {
		t.Fatalf("Check(db:read, asset) = %v, %v; want true (base via same_object)", ok, err)
	}
	// guard: a capability neither role has → false.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:admin"); err != nil || ok {
		t.Fatalf("Check(db:admin, asset) = %v, %v; want false", ok, err)
	}
}

// TestCheckGlobCapabilities pins the SQL→Go glob path in Check: a role's stored
// capability patterns are matched against the concrete requested capability via
// CapMatch. Each subcase binds a role STANDING on the asset with a distinct
// capability pattern and asserts positive/negative Check outcomes.
func TestCheckGlobCapabilities(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "glob@x", DisplayName: "Glob"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "glob-folder"})
	if err != nil {
		t.Fatal(err)
	}

	// bindRole creates a role with the given capability patterns and a STANDING
	// binding of it to `user` on a fresh asset, returning that asset id.
	bindRole := func(name string, patterns ...string) uuid.UUID {
		asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: name + "-asset", Labels: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name, ResourceType: "asset", Capabilities: caps(patterns...)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: role.ID, ScopeAssetID: pgUUID(asset.ID), SubjectUserID: pgUUID(user.ID),
		}); err != nil {
			t.Fatal(err)
		}
		return asset.ID
	}

	type want struct {
		cap string
		ok  bool
	}
	cases := []struct {
		name     string
		patterns []string
		wants    []want
	}{
		{"k8s-dstar", []string{"k8s:**"}, []want{
			{"k8s:connect", true},
			{"k8s:impersonate:cluster-admin", true},
		}},
		{"k8s-star", []string{"k8s:*"}, []want{
			{"k8s:connect", true},
			{"k8s:impersonate:cluster-admin", false},
		}},
		{"k8s-impersonate-star", []string{"k8s:impersonate:*"}, []want{
			{"k8s:impersonate:cluster-admin", true},
			{"k8s:connect", false},
		}},
		{"db-ddl-concrete", []string{"db:ddl"}, []want{
			{"db:ddl", true},
			{"db:connect", false},
		}},
		{"star-connect", []string{"*:connect"}, []want{
			{"ssh:connect", true},
			{"db:connect", true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := bindRole(tc.name, tc.patterns...)
			for _, w := range tc.wants {
				got, err := a.Check(ctx, user.ID, asset, w.cap)
				if err != nil {
					t.Fatalf("Check(%q): %v", w.cap, err)
				}
				if got != w.ok {
					t.Fatalf("Check(patterns=%v, %q) = %v, want %v", tc.patterns, w.cap, got, w.ok)
				}
			}
		})
	}
}

func TestRolesOnAsset(t *testing.T) {
	pool := newPool(t)
	alice, pgprod, _, pgstaging, _, operatorRole, viewerRole, dbaRole := seed(t, pool)
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

	// pgstaging: alice holds `viewer` Active (via the sre→staging standing binding
	// + parent cascade), and `dba` is Requestable (request_policy names viewer as
	// requester_role, and alice holds viewer). dba is NOT active.
	r2, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Active) != 1 || r2.Active[0] != viewerRole {
		t.Fatalf("pgstaging active = %v, want [viewer]", r2.Active)
	}
	if len(r2.Requestable) != 1 || r2.Requestable[0] != dbaRole {
		t.Fatalf("pgstaging requestable = %v, want [dba]", r2.Requestable)
	}
}

// TestRequestableRequesterRoleViaNestedGroupCascade pins that the requester-role
// eligibility predicate honors BOTH nested-group membership AND the parent-folder
// cascade at once: the requester_role is bound to an OUTER group on a GRANDPARENT
// folder, the user is a member only via a doubly-nested group, and the target
// asset is two folders below the binding — reachable only through the role's
// `parent` self-grant. If either the group closure or the cascade were dropped,
// the role would not be requestable.
func TestRequestableRequesterRoleViaNestedGroupCascade(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	dave, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "dave@x", DisplayName: "Dave"})
	if err != nil {
		t.Fatal(err)
	}
	// dave ∈ inner ∈ outer (doubly nested).
	outer, err := q.CreateGroup(ctx, "outer")
	if err != nil {
		t.Fatal(err)
	}
	inner, err := q.CreateGroup(ctx, "inner")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: inner.ID, MemberUserID: pgUUID(dave.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: outer.ID, MemberGroupID: pgUUID(inner.ID)}); err != nil {
		t.Fatal(err)
	}

	// gp ⊃ mid ⊃ leaf; asset deep ∈ leaf.
	gp, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "casc-gp"})
	if err != nil {
		t.Fatal(err)
	}
	mid, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "casc-mid", ParentID: pgUUID(gp.ID)})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "casc-leaf", ParentID: pgUUID(mid.ID)})
	if err != nil {
		t.Fatal(err)
	}
	deep, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: leaf.ID, Name: "casc-deep", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	prereq, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "casc-prereq", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	target, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "casc-target", ResourceType: "asset", Capabilities: caps("db:admin")})
	if err != nil {
		t.Fatal(err)
	}
	// prereq cascades down folders → dave holds prereq on `deep`.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: prereq.ID, SourceRoleID: prereq.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// STANDING prereq → outer group on the GRANDPARENT folder.
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: prereq.ID, ScopeFolderID: pgUUID(gp.ID), SubjectGroupID: pgUUID(outer.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// Policy: target requestable on `deep`, requester_role = prereq.
	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: target.ID, ScopeAssetID: pgUUID(deep.ID), RequiredApprovals: 1, RequesterRoleID: pgUUID(prereq.ID),
	}); err != nil {
		t.Fatal(err)
	}

	roles, err := a.RolesOnAsset(ctx, dave.ID, deep.ID)
	if err != nil {
		t.Fatal(err)
	}
	// dave holds prereq Active on deep (via nested group + cascade) → target Requestable.
	if len(roles.Active) != 1 || roles.Active[0] != prereq.ID {
		t.Fatalf("deep active = %v, want [prereq]", roles.Active)
	}
	if len(roles.Requestable) != 1 || roles.Requestable[0] != target.ID {
		t.Fatalf("deep requestable = %v, want [target] (requester_role held via nested group + cascade)", roles.Requestable)
	}
}
