package authz

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	q := sqlc.New(pool)

	au, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	sre, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "sre"})
	if err != nil {
		t.Fatal(err)
	}
	platform, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: sre.ID, MemberUserID: pgUUID(au.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, sqlc.AddGroupToGroupParams{GroupID: platform.ID, MemberGroupID: pgUUID(sre.ID)}); err != nil {
		t.Fatal(err)
	}

	prod, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	proddb, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-db", ParentID: pgUUID(prod.ID)})
	if err != nil {
		t.Fatal(err)
	}
	staging, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "secret"})
	if err != nil {
		t.Fatal(err)
	}

	mkAsset := func(folder uuid.UUID, name string) uuid.UUID {
		a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	pgprod = mkAsset(proddb.ID, "pg-prod")
	apiprod = mkAsset(prod.ID, "api-prod")
	pgstaging = mkAsset(staging.ID, "pg-staging")
	topsecret = mkAsset(secret.ID, "top-secret")

	op := createRoleWithCaps(t, ctx, q, "operator", pgtype.UUID{}, caps("ssh:connect", "db:read", "db:write"))
	vw := createRoleWithCaps(t, ctx, q, "viewer", pgtype.UUID{}, caps("db:read"))
	dba := createRoleWithCaps(t, ctx, q, "dba", pgtype.UUID{}, caps("db:admin"))

	// operator + viewer cascade down folders via explicit parent self-rules.
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: op.ID, SourceRoleID: op.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: vw.ID, SourceRoleID: vw.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}

	// STANDING: platform -> operator on prod (⇒ pgprod, apiprod active for alice).
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: op.ID, ScopeFolderID: pgUUID(prod.ID), SubjectGroupID: pgUUID(platform.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// STANDING: sre -> viewer on staging (⇒ alice holds viewer on pgstaging via cascade).
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: vw.ID, ScopeFolderID: pgUUID(staging.ID), SubjectGroupID: pgUUID(sre.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// request_policy: dba requestable on pgstaging, requester_role=viewer.
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: dba.ID, ScopeAssetID: pgUUID(pgstaging), RequiredApprovals: 1, RequesterRoleID: pgUUID(vw.ID),
	}); err != nil {
		t.Fatal(err)
	}

	return au.ID, pgprod, apiprod, pgstaging, topsecret, op.ID, vw.ID, dba.ID
}

// grantOpts controls the timing/state of a fabricated access_grant row.
type grantOpts struct {
	expiresIn time.Duration // grant expires_at = now() + expiresIn (may be negative → already expired)
	revoked   bool          // revoked_at = now()
}

// fabricateGrant inserts a minimal access_requests row (T3 mints these; here we
// fabricate) and an access_grants row for (user, role, asset) with the given
// timing/state, returning the grant id. It bypasses the sqlc CreateAccessGrant
// query (which cannot set expires_at in the past or revoked_at) by writing the
// row directly so the active/expired/revoked matrix is exercisable.
func fabricateGrant(t *testing.T, pool *pgxpool.Pool, user, role, asset uuid.UUID, o grantOpts) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var reqID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_requests (requester_user_id, role_id, asset_id, requested_duration, required_approvals, granted_duration, status, resolved_at)
VALUES ($1, $2, $3, '1 hour', 1, '1 hour', 'granted', now())
RETURNING id`, user, role, asset).Scan(&reqID); err != nil {
		t.Fatalf("fabricate access_request: %v", err)
	}
	var grantID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_grants (request_id, role_id, scope_asset_id, subject_user_id, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, now() + $5::interval, CASE WHEN $6::bool THEN now() ELSE NULL END)
RETURNING id`, reqID, role, asset, user, o.expiresIn.String(), o.revoked).Scan(&grantID); err != nil {
		t.Fatalf("fabricate access_grant: %v", err)
	}
	return grantID
}

// TestGrantConfersAccess (T2.1): an active grant of dba on pgstaging confers
// dba's capability and lists dba Active, exactly like a standing binding.
func TestGrantConfersAccess(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	// Pre: alice does NOT hold dba's db:admin on pgstaging (only Requestable there).
	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || ok {
		t.Fatalf("pre: Check(db:admin) = %v, %v; want false", ok, err)
	}

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour})

	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || !ok {
		t.Fatalf("Check(db:admin, pgstaging) after grant = %v, %v; want true", ok, err)
	}
	roles, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	activeHasDBA := false
	for _, r := range roles.Active {
		if r == dbaRole {
			activeHasDBA = true
		}
	}
	if !activeHasDBA {
		t.Fatalf("dba must be Active via grant; got .Active=%v", roles.Active)
	}
}

// TestGrantFlowsThroughRewriteGraph (T2.2): a granted role composes through the
// role_grants rewrite closure. editor ⊇ owner via same_object; grant owner on an
// asset; editor's exclusive capability must be conferred and HoldsRole(editor)
// must be true.
func TestGrantFlowsThroughRewriteGraph(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)
	rr := NewRoleResolver(pool)

	alice, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "grantflow@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "gf-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "gf-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	owner := createRoleWithCaps(t, ctx, q, "gf-owner", pgtype.UUID{}, caps("db:read"))
	editor := createRoleWithCaps(t, ctx, q, "gf-editor", pgtype.UUID{}, caps("db:write"))
	// editor ⊇ owner via same_object: goal editor reduces to source owner, so
	// holding owner confers editor on the same object.
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: editor.ID, SourceRoleID: owner.ID, Via: "same_object"}); err != nil {
		t.Fatal(err)
	}

	fabricateGrant(t, pool, alice.ID, owner.ID, asset.ID, grantOpts{expiresIn: time.Hour})

	// editor is held via the grant of owner composing through same_object.
	holds, err := rr.HoldsRole(ctx, alice.ID, editor.ID, "asset", asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !holds {
		t.Fatal("HoldsRole(editor) via granted owner + same_object rewrite = false, want true")
	}
	// editor's exclusive capability (db:write) is conferred.
	if ok, err := a.Check(ctx, alice.ID, asset.ID, "db:write"); err != nil || !ok {
		t.Fatalf("Check(db:write) via granted owner→editor = %v, %v; want true", ok, err)
	}
	// owner's own capability holds too.
	if ok, err := a.Check(ctx, alice.ID, asset.ID, "db:read"); err != nil || !ok {
		t.Fatalf("Check(db:read) via grant = %v, %v; want true", ok, err)
	}
}

// TestExpiredGrantDoesNotConfer (T2.3): a grant with expires_at in the past does
// not confer — no reaper needed, expiry is enforced at query time via now().
func TestExpiredGrantDoesNotConfer(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: -time.Minute})

	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || ok {
		t.Fatalf("Check(db:admin) with expired grant = %v, %v; want false", ok, err)
	}
	roles, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles.Active {
		if r == dbaRole {
			t.Fatalf("expired grant must NOT make dba Active; got .Active=%v", roles.Active)
		}
	}
}

// TestRevokedGrantDoesNotConfer (T2.4): a grant with revoked_at set does not
// confer immediately, without any reaper.
func TestRevokedGrantDoesNotConfer(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour, revoked: true})

	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || ok {
		t.Fatalf("Check(db:admin) with revoked grant = %v, %v; want false", ok, err)
	}
	roles, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles.Active {
		if r == dbaRole {
			t.Fatalf("revoked grant must NOT make dba Active; got .Active=%v", roles.Active)
		}
	}
}

// TestActiveGrantExcludesRequestable (T2.5): once alice has an active grant for a
// role that was Requestable for her on the asset, it moves to .Active and is
// removed from .Requestable — the requestable "held" sub-CTE now includes the
// grant, so active-exclusion subtracts it.
func TestActiveGrantExcludesRequestable(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	// Pre: dba is Requestable (not Active) for alice on pgstaging.
	pre, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre.Requestable) != 1 || pre.Requestable[0] != dbaRole {
		t.Fatalf("pre: pgstaging requestable = %v, want [dba]", pre.Requestable)
	}

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour})

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
		t.Fatalf("post: dba must be Active via grant; got .Active=%v", post.Active)
	}
	for _, r := range post.Requestable {
		if r == dbaRole {
			t.Fatalf("post: dba must NOT be Requestable once granted Active; got .Requestable=%v", post.Requestable)
		}
	}
}

// TestExplainRoleReflectsGrant (T2.6): ExplainRole surfaces the grant as the base
// of a satisfying derivation path (holds=true, ≥1 path).
func TestExplainRoleReflectsGrant(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	rr := NewRoleResolver(pool)

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour})

	holds, paths, err := rr.ExplainRole(ctx, alice, dbaRole, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	if !holds || len(paths) == 0 {
		t.Fatalf("ExplainRole via grant: holds=%v paths=%d, want holds=true with ≥1 path", holds, len(paths))
	}
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	carol, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "carol@x", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	// carol ∈ subteam ∈ contractors (nested group, group-aware subject matching).
	contractors, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "contractors"})
	if err != nil {
		t.Fatal(err)
	}
	subteam, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "subteam"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: subteam.ID, MemberUserID: pgUUID(carol.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, sqlc.AddGroupToGroupParams{GroupID: contractors.ID, MemberGroupID: pgUUID(subteam.ID)}); err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "bg-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "bg-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	breakglass := createRoleWithCaps(t, ctx, q, "breakglass", pgtype.UUID{}, caps("db:admin"))
	// Policy with NO requester_role — eligibility is ONLY via explicit subjects.
	pol, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: breakglass.ID, ScopeAssetID: pgUUID(asset.ID), RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	bob, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "bob-ineligible@x", DisplayName: "Bob"})
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
	q := sqlc.New(pool)
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
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	q := sqlc.New(pool)

	alice, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(alice.ID)}); err != nil {
		t.Fatal(err)
	}

	gp, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "gp"})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "parent", ParentID: pgUUID(gp.ID)})
	if err != nil {
		t.Fatal(err)
	}
	child, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "child", ParentID: pgUUID(parent.ID)})
	if err != nil {
		t.Fatal(err)
	}

	deepAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: child.ID, Name: "deep", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	role := createRoleWithCaps(t, ctx, q, "op3", pgtype.UUID{}, caps("db:read"))
	// op3 cascades down folders via an explicit parent self-rule.
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: role.ID, SourceRoleID: role.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// standing binding on the GRANDPARENT folder
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "cascade@x", DisplayName: "Cascade"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "cascade-grp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}

	parent, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "cascade-parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "cascade-child", ParentID: pgUUID(parent.ID)})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: child.ID, Name: "cascade-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	op := createRoleWithCaps(t, ctx, q, "cascade-op", pgtype.UUID{}, caps("db:read"))
	// STANDING binding of op to the group on the PARENT folder. No role_grant yet.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: op.ID, SourceRoleID: op.ID, Via: "parent"}); err != nil {
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
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "compose@x", DisplayName: "Compose"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "compose-grp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "compose-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "compose-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	base := createRoleWithCaps(t, ctx, q, "compose-base", pgtype.UUID{}, caps("db:read"))
	super := createRoleWithCaps(t, ctx, q, "compose-super", pgtype.UUID{}, caps("db:write"))
	// Rule: holding super on O confers base on O. In role_grants terms the goal
	// `base` reduces to source `super` (role_id=base, source_role_id=super), so the
	// forward closure adds base whenever super is held. (This is the (base ⊇ super)
	// direction — "base is conferred by super" — matching the goal-expansion engine
	// where WHERE rg.source_role_id = h.role_id SELECT rg.role_id.)
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: base.ID, SourceRoleID: super.ID, Via: "same_object"}); err != nil {
		t.Fatal(err)
	}
	// STANDING binding of super to the group on the asset.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "glob@x", DisplayName: "Glob"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "glob-folder"})
	if err != nil {
		t.Fatal(err)
	}

	// bindRole creates a role with the given capability patterns and a STANDING
	// binding of it to `user` on a fresh asset, returning that asset id.
	bindRole := func(name string, patterns ...string) uuid.UUID {
		asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: name + "-asset", Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatal(err)
		}
		role := createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, caps(patterns...))
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	dave, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "dave@x", DisplayName: "Dave"})
	if err != nil {
		t.Fatal(err)
	}
	// dave ∈ inner ∈ outer (doubly nested).
	outer, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "outer"})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "inner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: inner.ID, MemberUserID: pgUUID(dave.ID)}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddGroupToGroup(ctx, sqlc.AddGroupToGroupParams{GroupID: outer.ID, MemberGroupID: pgUUID(inner.ID)}); err != nil {
		t.Fatal(err)
	}

	// gp ⊃ mid ⊃ leaf; asset deep ∈ leaf.
	gp, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "casc-gp"})
	if err != nil {
		t.Fatal(err)
	}
	mid, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "casc-mid", ParentID: pgUUID(gp.ID)})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "casc-leaf", ParentID: pgUUID(mid.ID)})
	if err != nil {
		t.Fatal(err)
	}
	deep, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: leaf.ID, Name: "casc-deep", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	prereq := createRoleWithCaps(t, ctx, q, "casc-prereq", pgtype.UUID{}, caps("db:read"))
	target := createRoleWithCaps(t, ctx, q, "casc-target", pgtype.UUID{}, caps("db:admin"))
	// prereq cascades down folders → dave holds prereq on `deep`.
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: prereq.ID, SourceRoleID: prereq.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// STANDING prereq → outer group on the GRANDPARENT folder.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: prereq.ID, ScopeFolderID: pgUUID(gp.ID), SubjectGroupID: pgUUID(outer.ID),
	}); err != nil {
		t.Fatal(err)
	}
	// Policy: target requestable on `deep`, requester_role = prereq.
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
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

// TestCapabilitiesOnAsset pins the one-query connect-path primitive: a user
// holding a role with ssh:login:deploy via a STANDING binding on the asset gets a
// Capabilities set whose Allows/EntitledLogins reproduce Check exactly. The set is
// fetched once and answers multiple capability questions.
func TestCapabilitiesOnAsset(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "cap-on-asset@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "cap-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "cap-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "cap-deploy", pgtype.UUID{}, caps("ssh:login:deploy"))
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgUUID(asset.ID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	capsSet, err := a.CapabilitiesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatalf("CapabilitiesOnAsset: %v", err)
	}
	if !capsSet.Allows("ssh:login:deploy") {
		t.Fatalf("Allows(ssh:login:deploy) = false, want true; caps=%v", capsSet)
	}
	if capsSet.Allows("ssh:login:other") {
		t.Fatalf("Allows(ssh:login:other) = true, want false; caps=%v", capsSet)
	}
	if capsSet.Allows("ssh:record:exempt") {
		t.Fatalf("Allows(ssh:record:exempt) = true, want false; caps=%v", capsSet)
	}

	// EntitledLogins intersects order-preserving with only the held login.
	logins, err := EntitledLogins(ctx, a, user.ID, asset.ID, []string{"deploy", "other"})
	if err != nil {
		t.Fatalf("EntitledLogins: %v", err)
	}
	if len(logins) != 1 || logins[0] != "deploy" {
		t.Fatalf("EntitledLogins = %v, want [deploy]", logins)
	}

	// Check still agrees with the pre-refactor behavior (built on the same set).
	if ok, err := a.Check(ctx, user.ID, asset.ID, "ssh:login:deploy"); err != nil || !ok {
		t.Fatalf("Check(ssh:login:deploy) = %v, %v; want true", ok, err)
	}
	if ok, err := a.Check(ctx, user.ID, asset.ID, "ssh:login:other"); err != nil || ok {
		t.Fatalf("Check(ssh:login:other) = %v, %v; want false", ok, err)
	}
}

// TestHoldsRoleStandingExcludesGrants (M3c T5): for a purely-granted role,
// HoldsRole (access membership) is true but HoldsRoleStanding (governance
// membership) is false; for a standing-bound role, both are true.
func TestHoldsRoleStandingExcludesGrants(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	rr := NewRoleResolver(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "hrs@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "hrs-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "hrs-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	granted := createRoleWithCaps(t, ctx, q, "hrs-granted", pgtype.UUID{}, caps())
	standing := createRoleWithCaps(t, ctx, q, "hrs-standing", pgtype.UUID{}, caps())

	// granted: held ONLY via an active JIT grant.
	fabricateGrant(t, pool, user.ID, granted.ID, asset.ID, grantOpts{expiresIn: time.Hour})
	// standing: held via a standing binding.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: standing.ID, ScopeAssetID: pgUUID(asset.ID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Granted role: HoldsRole true, HoldsRoleStanding false.
	if ok, err := rr.HoldsRole(ctx, user.ID, granted.ID, "asset", asset.ID); err != nil || !ok {
		t.Fatalf("HoldsRole(granted) = %v, %v; want true", ok, err)
	}
	if ok, err := rr.HoldsRoleStanding(ctx, user.ID, granted.ID, "asset", asset.ID); err != nil || ok {
		t.Fatalf("HoldsRoleStanding(granted) = %v, %v; want false (grants excluded)", ok, err)
	}

	// Standing role: both true.
	if ok, err := rr.HoldsRole(ctx, user.ID, standing.ID, "asset", asset.ID); err != nil || !ok {
		t.Fatalf("HoldsRole(standing) = %v, %v; want true", ok, err)
	}
	if ok, err := rr.HoldsRoleStanding(ctx, user.ID, standing.ID, "asset", asset.ID); err != nil || !ok {
		t.Fatalf("HoldsRoleStanding(standing) = %v, %v; want true", ok, err)
	}
}

// TestGrantedRequesterRoleNotRequestable (M3c T2 governance): when the requester
// role of a policy is held ONLY via an active JIT grant, the downstream role must
// NOT become Requestable (governance uses the standing-only closure). A STANDING
// binding of the requester role flips it to Requestable.
func TestGrantedRequesterRoleNotRequestable(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "grr@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "grr-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "grr-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	requester := createRoleWithCaps(t, ctx, q, "grr-requester", pgtype.UUID{}, caps())
	target := createRoleWithCaps(t, ctx, q, "grr-target", pgtype.UUID{}, caps("db:admin"))
	// Policy: target requestable on asset, requester_role = requester.
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: target.ID, ScopeAssetID: pgUUID(asset.ID), RequiredApprovals: 1, RequesterRoleID: pgUUID(requester.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// user holds requester ONLY via an active JIT grant.
	fabricateGrant(t, pool, user.ID, requester.ID, asset.ID, grantOpts{expiresIn: time.Hour})

	// requester is Active (access membership via grant), but target must NOT be
	// Requestable — the requester predicate is standing-only.
	roles, err := a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	activeHasRequester := false
	for _, r := range roles.Active {
		if r == requester.ID {
			activeHasRequester = true
		}
	}
	if !activeHasRequester {
		t.Fatalf("requester must be Active via grant; got .Active=%v", roles.Active)
	}
	for _, r := range roles.Requestable {
		if r == target.ID {
			t.Fatalf("target must NOT be Requestable when requester_role held only via grant; got .Requestable=%v", roles.Requestable)
		}
	}
	// asset must not be Requestable-visible for target either.
	vis, err := a.VisibleAssets(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, av := range vis {
		if av.AssetID == asset.ID {
			for _, r := range av.RoleIDs {
				if r == target.ID {
					t.Fatalf("target must NOT be Requestable-visible via granted requester_role; got roles=%v", av.RoleIDs)
				}
			}
		}
	}

	// Now give a STANDING binding of the requester role → target becomes Requestable.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: requester.ID, ScopeAssetID: pgUUID(asset.ID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatal(err)
	}
	roles2, err := a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	targetRequestable := false
	for _, r := range roles2.Requestable {
		if r == target.ID {
			targetRequestable = true
		}
	}
	if !targetRequestable {
		t.Fatalf("target must be Requestable once requester_role held STANDING; got .Requestable=%v", roles2.Requestable)
	}
}

// TestActiveExclusionStillCountsGrants (M3c T4 regression): a role held Active via
// a grant is NOT double-offered in .Requestable — active-exclusion keeps the grant
// arm. Uses the seed's request_policy(dba, pgstaging): granting dba on pgstaging
// makes it Active there, so it must drop out of Requestable.
func TestActiveExclusionStillCountsGrants(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	// Pre: dba is Requestable on pgstaging (alice holds viewer requester standing).
	pre, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	preRequestable := false
	for _, r := range pre.Requestable {
		if r == dbaRole {
			preRequestable = true
		}
	}
	if !preRequestable {
		t.Fatalf("pre: dba must be Requestable on pgstaging; got .Requestable=%v", pre.Requestable)
	}

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour})

	post, err := a.RolesOnAsset(ctx, alice, pgstaging)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range post.Active {
		if r == dbaRole {
			goto activeOK
		}
	}
	t.Fatalf("post: dba must be Active via grant; got .Active=%v", post.Active)
activeOK:
	for _, r := range post.Requestable {
		if r == dbaRole {
			t.Fatalf("post: dba must NOT be Requestable once granted Active (active-exclusion counts grants); got .Requestable=%v", post.Requestable)
		}
	}
}
