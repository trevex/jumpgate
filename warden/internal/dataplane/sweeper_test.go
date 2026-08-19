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

// sweepFixture seeds an ssh asset with allowed_logins {deploy}, a role carrying
// ssh:login:deploy, and a user. Sessions and login sources are attached per-scenario.
type sweepFixture struct {
	pool *pgxpool.Pool
	q    *gen.Queries
	ctx  context.Context
	reg  *dataplane.Registry
	term *dataplane.Terminator
	swp  *dataplane.Sweeper

	user  uuid.UUID
	asset uuid.UUID
	role  uuid.UUID
}

func setupSweep(t *testing.T) *sweepFixture {
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

	az := authz.NewSQLAuthorizer(pool)
	reg := dataplane.NewRegistry()
	term := dataplane.NewTerminator(pool, az, audit.New(pool))
	return &sweepFixture{
		pool: pool, q: q, ctx: ctx,
		reg:  reg,
		term: term,
		swp:  dataplane.NewSweeper(pool, reg, term),
		user: user.ID, asset: asset.ID, role: role.ID,
	}
}

// registerWorker adds a teardown sink for workerID so it counts as connected on this
// replica. Returns the sink (already registered).
func (f *sweepFixture) registerWorker(workerID string) chan dataplane.Signal {
	ch := make(chan dataplane.Signal, 8)
	f.reg.Add(workerID, ch)
	return ch
}

// bindStanding attaches a standing role_binding of the role on the asset to the user.
func (f *sweepFixture) bindStanding(t *testing.T) {
	t.Helper()
	if _, err := f.q.CreateRoleBinding(f.ctx, gen.CreateRoleBindingParams{
		RoleID: f.role, ScopeAssetID: pg(f.asset), SubjectUserID: pg(f.user),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// deleteBinding removes the standing role_binding (also fires NOTIFY authz_changed).
func (f *sweepFixture) deleteBinding(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM role_bindings WHERE role_id = $1 AND subject_user_id = $2`, f.role, f.user); err != nil {
		t.Fatalf("delete role binding: %v", err)
	}
}

// seedSession inserts a live_sessions row for (user,asset) owned by workerID.
func (f *sweepFixture) seedSession(t *testing.T, workerID string) uuid.UUID {
	t.Helper()
	sess, err := f.q.InsertLiveSession(f.ctx, gen.InsertLiveSessionParams{
		ID: uuid.New(), UserID: f.user, AssetID: f.asset, WorkerID: workerID,
		GrantID: pgtype.UUID{}, Protocol: "ssh", Principals: []string{"deploy"}, ClientKeyFp: "fp",
	})
	if err != nil {
		t.Fatalf("InsertLiveSession: %v", err)
	}
	return sess.ID
}

func (f *sweepFixture) terminateRequestedAt(t *testing.T, sess uuid.UUID) pgtype.Timestamptz {
	t.Helper()
	var ts pgtype.Timestamptz
	if err := f.pool.QueryRow(f.ctx, `SELECT terminate_requested_at FROM live_sessions WHERE id = $1`, sess).Scan(&ts); err != nil {
		t.Fatalf("select terminate_requested_at: %v", err)
	}
	return ts
}

// sessionTerminatedCount drains the outbox and counts session.terminated entries.
func (f *sweepFixture) sessionTerminatedCount(t *testing.T) int {
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

// TestSweepOwnedTearsDownDeauthorizedOwnedSession: a session owned by a locally
// connected worker whose only login was a standing binding must be torn down once
// that binding is deleted.
func TestSweepOwnedTearsDownDeauthorizedOwnedSession(t *testing.T) {
	f := setupSweep(t)
	f.registerWorker("w1")
	f.bindStanding(t)
	sess := f.seedSession(t, "w1")

	// Remove the sole login source.
	f.deleteBinding(t)

	if err := f.swp.SweepOwned(f.ctx); err != nil {
		t.Fatalf("SweepOwned: %v", err)
	}

	if !f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("deauthorized owned session: terminate_requested_at must be non-NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestSweepOwnedSkipsUnownedSessions: a session owned by a worker NOT connected to
// this replica must be left untouched, even when deauthorized.
func TestSweepOwnedSkipsUnownedSessions(t *testing.T) {
	f := setupSweep(t)
	f.registerWorker("w1") // this replica owns only w1
	f.bindStanding(t)
	sess := f.seedSession(t, "w2") // session owned by an unconnected worker

	f.deleteBinding(t)

	if err := f.swp.SweepOwned(f.ctx); err != nil {
		t.Fatalf("SweepOwned: %v", err)
	}

	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("unowned session: terminate_requested_at must stay NULL")
	}
	if n := f.sessionTerminatedCount(t); n != 0 {
		t.Fatalf("session.terminated events = %d, want 0 (unowned untouched)", n)
	}
}

// TestSweepOwnedNoWorkers: with no connected workers, SweepOwned is a no-op and must
// not error (and must not query or tear down anything).
func TestSweepOwnedNoWorkers(t *testing.T) {
	f := setupSweep(t)
	f.bindStanding(t)
	sess := f.seedSession(t, "w1") // owned by w1, but w1 is NOT registered
	f.deleteBinding(t)

	if err := f.swp.SweepOwned(f.ctx); err != nil {
		t.Fatalf("SweepOwned: %v", err)
	}

	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("no connected workers: terminate_requested_at must stay NULL")
	}
}

// TestAuthzSweeperDebounceCoalesces (timing-tolerant): drive RunAuthzSweeper with a
// short debounce/interval, seed an owned deauthorized session, and assert the session
// is eventually torn down — driven by either the LISTEN notification (fired by the
// binding delete) or the periodic backstop. Asserts the EFFECT, not a sweep count.
func TestAuthzSweeperDebounceCoalesces(t *testing.T) {
	f := setupSweep(t)
	f.registerWorker("w1")
	f.bindStanding(t)
	sess := f.seedSession(t, "w1")

	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()

	done := make(chan struct{})
	go func() {
		f.swp.RunAuthzSweeper(ctx, 200*time.Millisecond, 20*time.Millisecond)
		close(done)
	}()

	// Deleting the binding both removes the sole login and fires NOTIFY authz_changed.
	// Fire a few extra notifications rapidly to exercise coalescing.
	f.deleteBinding(t)
	for i := 0; i < 5; i++ {
		if _, err := f.pool.Exec(f.ctx, "SELECT pg_notify('authz_changed', '')"); err != nil {
			t.Fatalf("pg_notify: %v", err)
		}
	}

	// Poll for the teardown effect.
	deadline := time.Now().Add(10 * time.Second)
	for !f.terminateRequestedAt(t, sess).Valid {
		if time.Now().After(deadline) {
			t.Fatal("session was not torn down within deadline")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Stop the sweeper and let the goroutine exit cleanly.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunAuthzSweeper did not exit after ctx cancel")
	}
}
