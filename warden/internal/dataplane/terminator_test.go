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
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	q    *sqlc.Queries
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
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, sqlc.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.5:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "deploy", Kind: "ca", SecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}

	role, err := createRoleCaps(ctx, q, "ssh-deploy", "ssh:login:deploy")
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	sess, err := q.InsertLiveSession(ctx, sqlc.InsertLiveSessionParams{
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
	if _, err := f.q.CreateRoleBinding(f.ctx, sqlc.CreateRoleBindingParams{
		RoleID: f.role, ScopeAssetID: pg(f.asset), SubjectUserID: pg(f.user),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// mkGrant mints an active JIT access_grant of the role to the user and returns its id.
func (f *termFixture) mkGrant(t *testing.T) uuid.UUID {
	t.Helper()
	req, err := f.q.CreateAccessRequest(f.ctx, sqlc.CreateAccessRequestParams{
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
	g, err := f.q.CreateAccessGrant(f.ctx, sqlc.CreateAccessGrantParams{
		RequestID: req.ID, RoleID: f.role, ScopeAssetID: f.asset, SubjectUserID: f.user,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
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

// sessionEndedCount drains the outbox and counts session.ended entries.
func (f *termFixture) sessionEndedCount(t *testing.T) int {
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
		if r.EventType == dataplane.EventSessionEnded {
			n++
		}
	}
	return n
}

// liveSessionExists reports whether the fixture's live_sessions row is still present.
func (f *termFixture) liveSessionExists(t *testing.T) bool {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM live_sessions WHERE id = $1`, f.sess).Scan(&n); err != nil {
		t.Fatalf("count live_sessions: %v", err)
	}
	return n > 0
}

// TestMarkEndedDeletesAndAuditsOnce: MarkEnded deletes the live_sessions row and
// enqueues exactly one session.ended event; a second call on the (now-gone) row is
// a clean no-op — still exactly one event (idempotent), and audit chain verifies.
func TestMarkEndedDeletesAndAuditsOnce(t *testing.T) {
	f := setupTerm(t)

	if err := f.term.MarkEnded(f.ctx, f.sess, "worker reconnected without session"); err != nil {
		t.Fatalf("MarkEnded (1): %v", err)
	}
	if f.liveSessionExists(t) {
		t.Fatal("MarkEnded: live_sessions row must be deleted")
	}
	if n := f.sessionEndedCount(t); n != 1 {
		t.Fatalf("session.ended events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}

	// Idempotent: the row is already gone, so the second call deletes 0 rows and
	// must NOT enqueue a duplicate session.ended.
	if err := f.term.MarkEnded(f.ctx, f.sess, "worker reconnected without session"); err != nil {
		t.Fatalf("MarkEnded (2): %v", err)
	}
	if n := f.sessionEndedCount(t); n != 1 {
		t.Fatalf("session.ended events after repeat = %d, want exactly 1 (idempotent)", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify (post-repeat): %v", err)
	}
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

// TestTerminateGrantIdempotent: sole-source setup (as in TestTerminateGrantKillsSoleSource),
// but TerminateGrant is called TWICE. The second call re-lists the already-terminating
// session (repeat teardown is the intended pattern for reconnect re-sync + cascade), and
// must NOT enqueue a duplicate session.terminated audit event.
func TestTerminateGrantIdempotent(t *testing.T) {
	f := setupTerm(t)
	gid := f.mkGrant(t)

	f.revokeGrant(t, gid)

	// Call teardown twice; the mark is guarded so the second flips 0 rows.
	if err := f.term.TerminateGrant(f.ctx, gid); err != nil {
		t.Fatalf("TerminateGrant (1): %v", err)
	}
	if err := f.term.TerminateGrant(f.ctx, gid); err != nil {
		t.Fatalf("TerminateGrant (2): %v", err)
	}

	if !f.terminateRequestedAt(t).Valid {
		t.Fatal("idempotent teardown: terminate_requested_at must be non-NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want exactly 1 (no duplicate on repeat)", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestReevaluateRedeliversTeardownAuditsOnce: sole-source setup (as in
// TestTerminateGrantKillsSoleSource) but Reevaluate is called TWICE. Teardown is
// level-triggered: the still-present terminating session is re-listed on the second
// pass and the NOTIFY is re-delivered so a dropped signal self-heals. The
// session.terminated audit event, by contrast, is recorded exactly once (only on the
// row's 0→terminating transition). Asserts: two notifications on session_teardown,
// terminate_requested_at set, and exactly one session.terminated audit event.
func TestReevaluateRedeliversTeardownAuditsOnce(t *testing.T) {
	f := setupTerm(t)
	gid := f.mkGrant(t)
	f.revokeGrant(t, gid)

	// Dedicated conn LISTENing on the teardown channel.
	conn, err := f.pool.Acquire(f.ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(f.ctx, "LISTEN session_teardown"); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	if err := f.term.Reevaluate(f.ctx, f.user, f.asset); err != nil {
		t.Fatalf("Reevaluate (1): %v", err)
	}
	if err := f.term.Reevaluate(f.ctx, f.user, f.asset); err != nil {
		t.Fatalf("Reevaluate (2): %v", err)
	}

	// Two teardown notifications must have been delivered (one per Reevaluate).
	for i := 0; i < 2; i++ {
		waitCtx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
		n, err := conn.Conn().WaitForNotification(waitCtx)
		cancel()
		if err != nil {
			t.Fatalf("WaitForNotification (%d): %v", i+1, err)
		}
		if n.Channel != "session_teardown" {
			t.Fatalf("notification channel = %q, want session_teardown", n.Channel)
		}
	}

	if !f.terminateRequestedAt(t).Valid {
		t.Fatal("re-delivered teardown: terminate_requested_at must be non-NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want exactly 1 (audit once across re-deliveries)", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// seedSecondSession inserts an ADDITIONAL live_sessions row for the fixture's user
// on a freshly created second asset owned by a different worker, so a user-wide
// eviction has more than one row to signal. Returns the new session id.
func (f *termFixture) seedSecondSession(t *testing.T) uuid.UUID {
	t.Helper()
	folder, err := f.q.CreateFolder(f.ctx, sqlc.CreateFolderParams{Name: uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := f.q.CreateAsset(f.ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg2", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	sess, err := f.q.InsertLiveSession(f.ctx, sqlc.InsertLiveSessionParams{
		ID: uuid.New(), UserID: f.user, AssetID: asset.ID, WorkerID: "worker-2",
		GrantID: pgtype.UUID{}, Protocol: "ssh", Principals: []string{"deploy"}, ClientKeyFp: "fp2",
	})
	if err != nil {
		t.Fatalf("InsertLiveSession (2): %v", err)
	}
	return sess.ID
}

func (f *termFixture) terminateRequestedAtOf(t *testing.T, sess uuid.UUID) pgtype.Timestamptz {
	t.Helper()
	var ts pgtype.Timestamptz
	if err := f.pool.QueryRow(f.ctx, `SELECT terminate_requested_at FROM live_sessions WHERE id = $1`, sess).Scan(&ts); err != nil {
		t.Fatalf("select terminate_requested_at: %v", err)
	}
	return ts
}

// TestTerminateUserEvictsAllSessions: a user with TWO live sessions (on different
// assets, owned by different workers) is evicted wholesale. Both rows get
// terminate_requested_at set, exactly two session.terminated audit events are
// recorded, and a second call is idempotent — it adds no further events.
func TestTerminateUserEvictsAllSessions(t *testing.T) {
	f := setupTerm(t)
	sess2 := f.seedSecondSession(t)

	n, err := f.term.TerminateUser(f.ctx, f.user, "user_deactivated")
	if err != nil {
		t.Fatalf("TerminateUser: %v", err)
	}
	if n != 2 {
		t.Fatalf("TerminateUser signalled %d sessions, want 2", n)
	}

	if !f.terminateRequestedAt(t).Valid {
		t.Fatal("session 1: terminate_requested_at must be non-NULL after eviction")
	}
	if !f.terminateRequestedAtOf(t, sess2).Valid {
		t.Fatal("session 2: terminate_requested_at must be non-NULL after eviction")
	}
	if c := f.sessionTerminatedCount(t); c != 2 {
		t.Fatalf("session.terminated events = %d, want 2", c)
	}

	// Idempotent: a second wholesale eviction re-signals the still-present rows but
	// records no additional session.terminated events.
	n, err = f.term.TerminateUser(f.ctx, f.user, "user_deactivated")
	if err != nil {
		t.Fatalf("TerminateUser (2): %v", err)
	}
	if n != 2 {
		t.Fatalf("TerminateUser (2) signalled %d sessions, want 2", n)
	}
	if c := f.sessionTerminatedCount(t); c != 2 {
		t.Fatalf("session.terminated events after repeat = %d, want exactly 2 (idempotent)", c)
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
