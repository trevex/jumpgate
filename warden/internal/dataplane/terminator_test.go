package dataplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Compile-time assertion that *dataplane.Terminator satisfies the seam.
var _ interface {
	TerminateGrant(context.Context, uuid.UUID) error
} = (*dataplane.Terminator)(nil)

// termFixture is a minimal seed for the terminator scenarios: an ssh asset with
// allowed_logins {deploy}, a role carrying ssh:login:deploy, a user, and a live
// session for (user,asset). Login sources (standing binding / JIT grant) are
// attached per-scenario by the test.
type termFixture struct {
	pool *pgxpool.Pool
	q    *gen.Queries
	ctx  context.Context
	term *dataplane.Terminator
	az   authz.Authorizer

	user  uuid.UUID
	asset uuid.UUID
	role  uuid.UUID
	sess  uuid.UUID
}

func setupTerm(t *testing.T) *termFixture {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, AllowedLogins: []string{"deploy"}, AuthMethod: "ca-cert", StoredSecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ssh_asset_config SET target_address = $1 WHERE asset_id = $2`, "10.0.0.5:22", asset.ID); err != nil {
		t.Fatalf("set target_address: %v", err)
	}

	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "ssh-deploy", ResourceType: "asset", Capabilities: capsJSON("ssh:login:deploy")})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	sess, err := q.InsertLiveSession(ctx, gen.InsertLiveSessionParams{
		ID: uuid.New(), UserID: user.ID, AssetID: asset.ID, WorkerID: "worker-1",
		GrantID: pgtype.UUID{}, Protocol: "ssh", Principals: []string{"deploy"}, ClientKeyFp: "fp",
	})
	if err != nil {
		t.Fatalf("InsertLiveSession: %v", err)
	}

	az := authz.NewSQLAuthorizer(pool)
	return &termFixture{
		pool: pool, q: q, ctx: ctx,
		term: dataplane.NewTerminator(pool, az, audit.New(pool)),
		az:   az,
		user: user.ID, asset: asset.ID, role: role.ID, sess: sess.ID,
	}
}

// bindStanding attaches a standing role_binding of the role on the asset.
func (f *termFixture) bindStanding(t *testing.T) {
	t.Helper()
	if _, err := f.q.CreateRoleBinding(f.ctx, gen.CreateRoleBindingParams{
		RoleID: f.role, ScopeAssetID: pg(f.asset), SubjectUserID: pg(f.user),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// mkGrant mints an active JIT access_grant of the role to the user and returns its id.
func (f *termFixture) mkGrant(t *testing.T) uuid.UUID {
	t.Helper()
	req, err := f.q.CreateAccessRequest(f.ctx, gen.CreateAccessRequestParams{
		RequesterUserID:   f.user,
		RoleID:            f.role,
		AssetID:           f.asset,
		Reason:            "seed",
		RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		RequiredApprovals: 0,
		GrantedDuration:   pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		Status:            "granted",
	})
	if err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	g, err := f.q.CreateAccessGrant(f.ctx, gen.CreateAccessGrantParams{
		RequestID: req.ID, RoleID: f.role, ScopeAssetID: f.asset, SubjectUserID: f.user,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	return g.ID
}

// revokeGrant marks the grant revoked directly (row survives so GetGrant still
// resolves the subject/asset, but the held closure no longer counts it).
func (f *termFixture) revokeGrant(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `UPDATE access_grants SET revoked_at = now() WHERE id = $1`, id); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}
}

func (f *termFixture) terminateRequestedAt(t *testing.T) pgtype.Timestamptz {
	t.Helper()
	var ts pgtype.Timestamptz
	if err := f.pool.QueryRow(f.ctx, `SELECT terminate_requested_at FROM live_sessions WHERE id = $1`, f.sess).Scan(&ts); err != nil {
		t.Fatalf("select terminate_requested_at: %v", err)
	}
	return ts
}

// sessionTerminatedCount drains the outbox and counts session.terminated entries.
func (f *termFixture) sessionTerminatedCount(t *testing.T) int {
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

// TestTerminateGrantKillsSoleSource: the JIT grant is the user's ONLY login source.
// Once revoked, EntitledLogins is empty → the live session must be torn down.
func TestTerminateGrantKillsSoleSource(t *testing.T) {
	f := setupTerm(t)
	gid := f.mkGrant(t)

	// Precondition: while the grant is active it confers the login.
	logins, err := authz.EntitledLogins(f.ctx, f.az, f.user, f.asset, []string{"deploy"})
	if err != nil {
		t.Fatalf("EntitledLogins (pre): %v", err)
	}
	if len(logins) != 1 || logins[0] != "deploy" {
		t.Fatalf("precondition: EntitledLogins = %v, want [deploy]", logins)
	}

	f.revokeGrant(t, gid)

	// Precondition: after revoke the grant no longer confers the login.
	logins, err = authz.EntitledLogins(f.ctx, f.az, f.user, f.asset, []string{"deploy"})
	if err != nil {
		t.Fatalf("EntitledLogins (post): %v", err)
	}
	if len(logins) != 0 {
		t.Fatalf("precondition: EntitledLogins after revoke = %v, want empty", logins)
	}

	if err := f.term.TerminateGrant(f.ctx, gid); err != nil {
		t.Fatalf("TerminateGrant: %v", err)
	}

	if !f.terminateRequestedAt(t).Valid {
		t.Fatal("sole-source revoke: terminate_requested_at must be non-NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestTerminateGrantKeepsStandingSession: the user holds BOTH a standing binding
// AND a JIT grant of the role. Revoking the grant must NOT tear down the session —
// the standing binding still confers the login. This is the critical property.
func TestTerminateGrantKeepsStandingSession(t *testing.T) {
	f := setupTerm(t)
	f.bindStanding(t)
	gid := f.mkGrant(t)

	// Revoke the grant so ONLY the standing binding remains.
	f.revokeGrant(t, gid)

	// Precondition: the standing binding ALONE still confers ssh:login:deploy.
	ok, err := f.az.Check(f.ctx, f.user, f.asset, "ssh:login:deploy")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !ok {
		t.Fatal("precondition: standing binding alone must confer ssh:login:deploy after revoke")
	}

	if err := f.term.TerminateGrant(f.ctx, gid); err != nil {
		t.Fatalf("TerminateGrant: %v", err)
	}

	if f.terminateRequestedAt(t).Valid {
		t.Fatal("standing login present: terminate_requested_at must stay NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 0 {
		t.Fatalf("session.terminated events = %d, want 0 (standing survives)", n)
	}
}
