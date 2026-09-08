package targetidentity_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/notification"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// fakeNotifier records enqueued events in memory; it ignores the tx querier since
// the scheduler's transactional behavior is covered by the notification package.
type fakeNotifier struct {
	mu     sync.Mutex
	events []notification.Event
}

func (f *fakeNotifier) Enqueue(_ context.Context, _ *sqlc.Queries, e notification.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeNotifier) byKind(kind string) []notification.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []notification.Event
	for _, e := range f.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// resetSchedules disables every schedule so a scheduler run under test sees only
// the schedules this test enables (the DB is shared across tests in the package).
func resetSchedules(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE target_identity_probe_schedules SET enabled = false`); err != nil {
		t.Fatalf("reset schedules: %v", err)
	}
}

// clearProbeQueue removes not-yet-terminal probe jobs left by earlier tests. The
// harness's claimAndComplete grabs the oldest queued job for the protocol across
// ALL assets, so a stray queued job would otherwise be completed against the wrong
// asset. Completed jobs/attempts/observations are immutable and left untouched.
func clearProbeQueue(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`DELETE FROM target_probe_jobs WHERE state IN ('queued','leased')`); err != nil {
		t.Fatalf("clear probe queue: %v", err)
	}
}

func schedule(t *testing.T, assetID uuid.UUID, interval time.Duration, freshness time.Duration) {
	t.Helper()
	fresh := pgtype.Int8{}
	if freshness > 0 {
		fresh = pgtype.Int8{Int64: int64(freshness / time.Second), Valid: true}
	}
	if _, err := sqlc.New(testPool).UpsertProbeSchedule(context.Background(), sqlc.UpsertProbeScheduleParams{
		AssetID: assetID, ProbeIntervalSeconds: int64(interval / time.Second), FreshnessSeconds: fresh, Enabled: true,
	}); err != nil {
		t.Fatalf("upsert schedule: %v", err)
	}
}

func periodicJobCount(t *testing.T, assetIDs ...uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM target_probe_jobs WHERE reason = 'periodic' AND asset_id = ANY($1)`, assetIDs).Scan(&n); err != nil {
		t.Fatalf("count periodic jobs: %v", err)
	}
	return n
}

func latestPeriodicNextAttempt(t *testing.T, assetID uuid.UUID) time.Time {
	t.Helper()
	var next time.Time
	if err := testPool.QueryRow(context.Background(),
		`SELECT next_attempt_at FROM target_probe_jobs WHERE reason='periodic' AND asset_id=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, assetID).Scan(&next); err != nil {
		t.Fatalf("read periodic next_attempt_at: %v", err)
	}
	return next
}

func newScheduler(env *targetIdentityEnv, notifier targetidentity.Notifier, jitter time.Duration, concurrency int, opts ...targetidentity.SchedulerOption) *targetidentity.Scheduler {
	return targetidentity.NewScheduler(testPool, env.svc, notifier, time.Minute, jitter, concurrency, opts...)
}

func TestSchedulerDisabledByDefaultQueuesNothing(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	resetSchedules(t)
	// No schedule row at all: nothing is due.
	sched := newScheduler(env, &fakeNotifier{}, 0, 8)
	if err := sched.QueueDueProbes(env.ctx); err != nil {
		t.Fatalf("queue due probes: %v", err)
	}
	if got := periodicJobCount(t, env.asset); got != 0 {
		t.Fatalf("queued %d periodic jobs with no schedule, want 0", got)
	}
	// A DISABLED schedule is also not due.
	schedule(t, env.asset, time.Second, 0)
	if _, err := testPool.Exec(env.ctx, `UPDATE target_identity_probe_schedules SET enabled=false WHERE asset_id=$1`, env.asset); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := sched.QueueDueProbes(env.ctx); err != nil {
		t.Fatalf("queue due probes (disabled): %v", err)
	}
	if got := periodicJobCount(t, env.asset); got != 0 {
		t.Fatalf("queued %d periodic jobs for disabled schedule, want 0", got)
	}
}

func TestSchedulerQueuesJitteredProbeWithinBounds(t *testing.T) {
	clearProbeQueue(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	jitter := 10 * time.Second

	for _, tc := range []struct {
		name string
		rand float64
		want time.Duration
	}{
		{"floor", 0, 0},
		{"mid", 0.5, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTargetIdentityEnv(t)
			resetSchedules(t)
			schedule(t, env.asset, 60*time.Second, 0) // fresh asset, no observation → due
			sched := newScheduler(env, &fakeNotifier{}, jitter, 8,
				targetidentity.WithSchedulerClock(func() time.Time { return base }),
				targetidentity.WithJitterSource(func() float64 { return tc.rand }))
			if err := sched.QueueDueProbes(env.ctx); err != nil {
				t.Fatalf("queue due probes: %v", err)
			}
			if got := periodicJobCount(t, env.asset); got != 1 {
				t.Fatalf("queued %d periodic jobs, want 1", got)
			}
			next := latestPeriodicNextAttempt(t, env.asset).UTC()
			delay := next.Sub(base)
			if delay < 0 || delay >= jitter {
				t.Fatalf("jitter delay %s out of bounds [0,%s)", delay, jitter)
			}
			if delay != tc.want {
				t.Fatalf("jitter delay %s, want %s", delay, tc.want)
			}
		})
	}
}

func TestSchedulerNoDuplicateForCurrentRevision(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	resetSchedules(t)
	schedule(t, env.asset, time.Second, 0)
	sched := newScheduler(env, &fakeNotifier{}, 0, 8)
	// Two ticks with the queued job still active: the NOT EXISTS guard and the
	// partial unique index keep exactly one active periodic job for the revision.
	if err := sched.QueueDueProbes(env.ctx); err != nil {
		t.Fatalf("queue tick 1: %v", err)
	}
	if err := sched.QueueDueProbes(env.ctx); err != nil {
		t.Fatalf("queue tick 2: %v", err)
	}
	if got := periodicJobCount(t, env.asset); got != 1 {
		t.Fatalf("queued %d periodic jobs across two ticks, want 1", got)
	}
}

func TestSchedulerPerAssetInterval(t *testing.T) {
	clearProbeQueue(t)
	due := newTargetIdentityEnv(t)    // no observation → due at any interval
	notDue := newTargetIdentityEnv(t) // recent success + long interval → not due
	notDue.complete(t, sshEvidence("per-asset"))
	resetSchedules(t)
	schedule(t, due.asset, time.Second, 0)
	schedule(t, notDue.asset, time.Hour, 0)

	sched := newScheduler(due, &fakeNotifier{}, 0, 8)
	if err := sched.QueueDueProbes(due.ctx); err != nil {
		t.Fatalf("queue due probes: %v", err)
	}
	if got := periodicJobCount(t, due.asset); got != 1 {
		t.Fatalf("due asset queued %d, want 1", got)
	}
	if got := periodicJobCount(t, notDue.asset); got != 0 {
		t.Fatalf("not-due asset queued %d, want 0", got)
	}
}

func TestSchedulerConcurrencyCap(t *testing.T) {
	clearProbeQueue(t)
	a := newTargetIdentityEnv(t)
	b := newTargetIdentityEnv(t)
	c := newTargetIdentityEnv(t)
	resetSchedules(t)
	for _, e := range []*targetIdentityEnv{a, b, c} {
		schedule(t, e.asset, time.Second, 0)
	}
	sched := newScheduler(a, &fakeNotifier{}, 0, 2) // cap = 2 per tick
	if err := sched.QueueDueProbes(a.ctx); err != nil {
		t.Fatalf("queue due probes: %v", err)
	}
	if got := periodicJobCount(t, a.asset, b.asset, c.asset); got != 2 {
		t.Fatalf("queued %d periodic jobs under cap 2, want 2", got)
	}
}

// waitForBlockedLock polls until some other backend is blocked waiting on a lock,
// giving the test a deterministic synchronization point (no sleeps) for the moment
// QueueDueProbes is stalled on the held asset row lock.
func waitForBlockedLock(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := testPool.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND pid <> pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatalf("poll blocked lock: %v", err)
		}
		if n >= 1 {
			return
		}
	}
	t.Fatal("timed out waiting for QueueDueProbes to block on the asset lock")
}

func TestSchedulerStaleRevisionSkippedBatchContinues(t *testing.T) {
	clearProbeQueue(t)
	stale := newTargetIdentityEnv(t)
	other := newTargetIdentityEnv(t)
	resetSchedules(t)
	schedule(t, stale.asset, time.Second, 0)
	schedule(t, other.asset, time.Second, 0)

	ctx := context.Background()
	// Hold a row lock on the stale asset. QueueProbeTx's FOR UPDATE re-read will block
	// on it; we then bump the revision and commit while it is blocked, so the locked
	// re-read sees a newer revision than the batch SELECT captured → ErrStaleRevision.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT endpoint_revision FROM assets WHERE id=$1 FOR UPDATE`, stale.asset); err != nil {
		t.Fatalf("lock stale asset: %v", err)
	}

	sched := newScheduler(stale, &fakeNotifier{}, 0, 8)
	done := make(chan error, 1)
	go func() { done <- sched.QueueDueProbes(ctx) }()

	waitForBlockedLock(t) // QueueDueProbes is now stalled on the stale asset's lock
	if _, err := tx.Exec(ctx, `UPDATE assets SET endpoint_revision = endpoint_revision + 1 WHERE id=$1`, stale.asset); err != nil {
		t.Fatalf("bump revision: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit bump: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("stale revision aborted the whole batch: %v", err)
	}
	if got := periodicJobCount(t, stale.asset); got != 0 {
		t.Fatalf("stale asset queued %d, want 0 (skipped)", got)
	}
	if got := periodicJobCount(t, other.asset); got != 1 {
		t.Fatalf("other due asset queued %d, want 1 (batch must continue past the stale skip)", got)
	}
}

func TestSchedulerReachabilityFailureDoesNotRevokeTrust(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	ev := sshEvidence("degraded")
	env.complete(t, ev)
	observations, err := env.svc.ListObservations(env.ctx, env.asset)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	env.approve(t, observations[0].ID, ev.Fingerprint, time.Time{})
	if got := env.status(t); got != targetidentity.StatusVerified {
		t.Fatalf("precondition status %q, want verified", got)
	}

	// Two failed periodic probes (a connectivity failure, not an identity change).
	for range 2 {
		env.queue(t, targetidentity.ProbeReasonPeriodic, uuid.Nil)
		env.claimAndComplete(t, targetidentity.ProbeFailed, targetidentity.FailureConnectionRefused)
	}

	resetSchedules(t)
	schedule(t, env.asset, time.Second, 0)
	notifier := &fakeNotifier{}
	sched := newScheduler(env, notifier, 0, 8, targetidentity.WithFailureThreshold(2))
	if err := sched.EnqueueNotifications(env.ctx); err != nil {
		t.Fatalf("enqueue notifications: %v", err)
	}

	// Trust is intact: the anchor is still active and status is still verified.
	if got := env.status(t); got != targetidentity.StatusVerified {
		t.Fatalf("status after failed probes %q, want verified (trust must not drop)", got)
	}
	var activeAnchors int
	if err := testPool.QueryRow(env.ctx,
		`SELECT count(*) FROM target_trust_anchors WHERE asset_id=$1 AND revoked_at IS NULL`, env.asset).Scan(&activeAnchors); err != nil {
		t.Fatalf("count anchors: %v", err)
	}
	if activeAnchors == 0 {
		t.Fatalf("anchor was revoked by a reachability failure; trust must survive")
	}
	// The degraded signal is a notification, not a state change.
	if got := notifier.byKind(notification.KindRepeatedProbeFailure); len(got) != 1 {
		t.Fatalf("repeated-failure notifications = %d, want 1", len(got))
	}
}

func TestSchedulerMismatchNotifiesWithoutRevoking(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	trusted := sshEvidence("trusted-host")
	env.complete(t, trusted)
	observations, err := env.svc.ListObservations(env.ctx, env.asset)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	env.approve(t, observations[0].ID, trusted.Fingerprint, time.Time{})

	// A periodic probe now observes a DIFFERENT host key → mismatch.
	env.queue(t, targetidentity.ProbeReasonPeriodic, uuid.Nil)
	env.claimAndComplete(t, targetidentity.ProbeSucceeded, "", sshEvidence("rotated-host"))
	if got := env.status(t); got != targetidentity.StatusIdentityChanged {
		t.Fatalf("status %q, want identity_changed", got)
	}

	resetSchedules(t)
	schedule(t, env.asset, time.Second, 0)
	notifier := &fakeNotifier{}
	sched := newScheduler(env, notifier, 0, 8)
	if err := sched.EnqueueNotifications(env.ctx); err != nil {
		t.Fatalf("enqueue notifications: %v", err)
	}
	if got := notifier.byKind(notification.KindIdentityMismatch); len(got) != 1 {
		t.Fatalf("identity-mismatch notifications = %d, want 1", len(got))
	}
	// The mismatch was reported, never auto-revoked: the original anchor stands.
	var activeAnchors int
	if err := testPool.QueryRow(env.ctx,
		`SELECT count(*) FROM target_trust_anchors WHERE asset_id=$1 AND revoked_at IS NULL`, env.asset).Scan(&activeAnchors); err != nil {
		t.Fatalf("count anchors: %v", err)
	}
	if activeAnchors == 0 {
		t.Fatalf("mismatch revoked the anchor; notifications must not change trust")
	}
}

func TestSchedulerApproachingAnchorExpiryNotifies(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	ev := sshEvidence("expiring")
	env.complete(t, ev)
	observations, err := env.svc.ListObservations(env.ctx, env.asset)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	// Anchor expires soon (inside the warn window).
	env.approve(t, observations[0].ID, ev.Fingerprint, time.Now().Add(12*time.Hour))

	resetSchedules(t)
	schedule(t, env.asset, time.Hour, 0) // no freshness policy
	notifier := &fakeNotifier{}
	sched := newScheduler(env, notifier, 0, 8, targetidentity.WithExpiryWarn(24*time.Hour))
	if err := sched.EnqueueNotifications(env.ctx); err != nil {
		t.Fatalf("enqueue notifications: %v", err)
	}
	got := notifier.byKind(notification.KindApproachingExpiry)
	if len(got) != 1 {
		t.Fatalf("approaching-expiry notifications = %d, want 1", len(got))
	}
}

func TestSchedulerApproachingFreshnessExpiryNotifies(t *testing.T) {
	clearProbeQueue(t)
	env := newTargetIdentityEnv(t)
	ev := sshEvidence("fresh")
	env.complete(t, ev)
	observations, err := env.svc.ListObservations(env.ctx, env.asset)
	if err != nil {
		t.Fatalf("list observations: %v", err)
	}
	env.approve(t, observations[0].ID, ev.Fingerprint, time.Time{}) // anchor never expires

	resetSchedules(t)
	schedule(t, env.asset, time.Hour, time.Hour) // freshness policy = 1h → expiry ~now+1h
	notifier := &fakeNotifier{}
	sched := newScheduler(env, notifier, 0, 8, targetidentity.WithExpiryWarn(24*time.Hour))
	if err := sched.EnqueueNotifications(env.ctx); err != nil {
		t.Fatalf("enqueue notifications: %v", err)
	}
	got := notifier.byKind(notification.KindApproachingExpiry)
	if len(got) != 1 {
		t.Fatalf("freshness approaching-expiry notifications = %d, want 1", len(got))
	}
	if got[0].Subject != "asset:"+env.asset.String() {
		t.Fatalf("notification subject = %q", got[0].Subject)
	}
}
