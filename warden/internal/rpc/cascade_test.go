package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// cascadeFixture wires the user-facing RPC server together with the standalone
// data-plane sweeper machinery, so a standing-authorization change made through
// the public API can be observed cascading into a live session teardown.
type cascadeFixture struct {
	pool  *pgxpool.Pool
	url   string
	acc   accessv1connect.AccessServiceClient
	admin string

	ctx   context.Context
	q     *gen.Queries
	reg   *dataplane.Registry
	swp   *dataplane.Sweeper
	user  uuid.UUID
	asset uuid.UUID
}

// setupCascade starts an RPC server, seeds an admin plus a subject user, an ssh
// asset that allows the "deploy" login, and registers worker "w1" as locally
// connected. Roles and role bindings are created by the caller through the API.
func setupCascade(t *testing.T) *cascadeFixture {
	t.Helper()
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	admin := adminToken(t, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ctx := context.Background()
	q := gen.New(pool)

	// Subject user whose data-plane access is under test.
	subject, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// SSH asset scaffolding: folder + asset + ssh config allowing the "deploy" login.
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.5:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "deploy", Kind: "ca", SecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}

	// A registry with "w1" registered marks that worker as owned by this replica,
	// so SweepOwned will re-evaluate its live sessions.
	reg := dataplane.NewRegistry()
	reg.Add("w1", make(chan dataplane.Signal, 8))
	term := dataplane.NewTerminator(pool, authz.NewSQLAuthorizer(pool), audit.New(pool))
	swp := dataplane.NewSweeper(pool, reg, term)

	return &cascadeFixture{
		pool: pool, url: url, acc: acc, admin: admin,
		ctx: ctx, q: q, reg: reg, swp: swp,
		user: subject.ID, asset: asset.ID,
	}
}

// createRole creates a role carrying ssh:login:deploy through the public API and
// returns its id.
func (f *cascadeFixture) createRole(t *testing.T, name string) string {
	t.Helper()
	r, err := f.acc.CreateRole(f.ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: name, ResourceType: "asset", Capabilities: []string{"ssh:login:deploy"},
	}), f.admin))
	if err != nil {
		t.Fatalf("CreateRole(%s): %v", name, err)
	}
	return r.Msg.Role.Id
}

// bindRoleOnAsset binds a role to the subject user at the asset scope through the
// public API and returns the binding id. The write path fires the authz_changed
// trigger.
func (f *cascadeFixture) bindRoleOnAsset(t *testing.T, roleID string) string {
	t.Helper()
	rb, err := f.acc.CreateRoleBinding(f.ctx, withToken(connect.NewRequest(&accessv1.CreateRoleBindingRequest{
		RoleId: roleID, ScopeAssetId: f.asset.String(), SubjectUserId: f.user.String(),
	}), f.admin))
	if err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
	return rb.Msg.Id
}

// deleteBinding removes a role binding through the public API.
func (f *cascadeFixture) deleteBinding(t *testing.T, bindingID string) {
	t.Helper()
	if _, err := f.acc.DeleteRoleBinding(f.ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleBindingRequest{
		Id: bindingID,
	}), f.admin)); err != nil {
		t.Fatalf("DeleteRoleBinding: %v", err)
	}
}

// seedSession inserts a live_sessions row for the subject user on the asset,
// owned by worker "w1".
func (f *cascadeFixture) seedSession(t *testing.T) uuid.UUID {
	t.Helper()
	sess, err := f.q.InsertLiveSession(f.ctx, gen.InsertLiveSessionParams{
		ID: uuid.New(), UserID: f.user, AssetID: f.asset, WorkerID: "w1",
		GrantID: pgtype.UUID{}, Protocol: "ssh", Principals: []string{"deploy"}, ClientKeyFp: "fp",
	})
	if err != nil {
		t.Fatalf("InsertLiveSession: %v", err)
	}
	return sess.ID
}

func (f *cascadeFixture) sweep(t *testing.T) {
	t.Helper()
	if err := f.swp.SweepOwned(f.ctx); err != nil {
		t.Fatalf("SweepOwned: %v", err)
	}
}

func (f *cascadeFixture) terminateRequestedAt(t *testing.T, sess uuid.UUID) pgtype.Timestamptz {
	t.Helper()
	var ts pgtype.Timestamptz
	if err := f.pool.QueryRow(f.ctx, `SELECT terminate_requested_at FROM live_sessions WHERE id = $1`, sess).Scan(&ts); err != nil {
		t.Fatalf("select terminate_requested_at: %v", err)
	}
	return ts
}

// sessionTerminatedCount fully drains the audit outbox and counts session.terminated
// entries.
func (f *cascadeFixture) sessionTerminatedCount(t *testing.T) int {
	t.Helper()
	for {
		n, err := audit.New(f.pool).DrainOnce(f.ctx, 256)
		if err != nil {
			t.Fatalf("DrainOnce: %v", err)
		}
		if n < 256 {
			break
		}
	}
	rows, err := f.q.ListAuditEntries(f.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.EventType == dataplane.EventSessionTerminated {
			n++
		}
	}
	return n
}

// TestCascadeDeleteRoleBindingTearsDownSession proves that deleting — through the
// public AccessService API — the standing role binding that is a user's sole login
// on an asset causes the sweeper to tear down that user's live session.
func TestCascadeDeleteRoleBindingTearsDownSession(t *testing.T) {
	f := setupCascade(t)

	roleID := f.createRole(t, "ssh-deploy")
	bindingID := f.bindRoleOnAsset(t, roleID)
	sess := f.seedSession(t)

	// While the binding stands, the sweep must be discriminating: it re-evaluates
	// the session, finds the login still authorized, and leaves it alone.
	f.sweep(t)
	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("authorized session: terminate_requested_at must stay NULL before revoke")
	}
	if n := f.sessionTerminatedCount(t); n != 0 {
		t.Fatalf("session.terminated events = %d, want 0 before revoke", n)
	}

	// Revoke the sole login via the API, then sweep.
	f.deleteBinding(t, bindingID)
	f.sweep(t)

	if !f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("deauthorized session: terminate_requested_at must be non-NULL after revoke")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestCascadeDeactivateUserTearsDownSession proves that deactivating a user through
// the public IdentityService API — when their sole login on an asset is a standing
// role binding — force-evicts their live session as part of the RPC itself, WITHOUT
// waiting for the background sweep. The handler's evictor (a real terminator wired
// through newServer→RegisterUserServices) signals teardown synchronously.
func TestCascadeDeactivateUserTearsDownSession(t *testing.T) {
	f := setupCascade(t)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, f.url)

	roleID := f.createRole(t, "ssh-deploy")
	f.bindRoleOnAsset(t, roleID)
	sess := f.seedSession(t)

	// Baseline: the session is authorized and untouched before deactivation.
	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("active user: terminate_requested_at must stay NULL before deactivation")
	}
	if n := f.sessionTerminatedCount(t); n != 0 {
		t.Fatalf("session.terminated events = %d, want 0 before deactivation", n)
	}

	// Deactivate the user via the real admin-authed RPC. No sweep — the eviction
	// must be an immediate, synchronous effect of the API call.
	if _, err := id.DeactivateUser(f.ctx, withToken(connect.NewRequest(&identityv1.DeactivateUserRequest{
		UserId: f.user.String(),
	}), f.admin)); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	if !f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("deactivated user: terminate_requested_at must be non-NULL after the RPC alone")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestCascadeStandingLoginSurvivesPartialRevoke is the control: with two standing
// bindings both conferring ssh:login:deploy, deleting one via the API leaves the
// session authorized, so the sweep must not tear it down.
func TestCascadeStandingLoginSurvivesPartialRevoke(t *testing.T) {
	f := setupCascade(t)

	roleA := f.createRole(t, "ssh-deploy-a")
	roleB := f.createRole(t, "ssh-deploy-b")
	bindingA := f.bindRoleOnAsset(t, roleA)
	f.bindRoleOnAsset(t, roleB)
	sess := f.seedSession(t)

	// Remove one of the two logins; the other still confers ssh:login:deploy.
	f.deleteBinding(t, bindingA)
	f.sweep(t)

	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("session retaining a standing login must not be torn down")
	}
	if n := f.sessionTerminatedCount(t); n != 0 {
		t.Fatalf("session.terminated events = %d, want 0 (login retained)", n)
	}
}
