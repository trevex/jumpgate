package notification_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/notification"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn, stop, err := testsupport.StartPostgresProcess()
	if err != nil {
		fmt.Fprintf(os.Stderr, "notification: start postgres: %v\n", err)
		os.Exit(1)
	}
	defer stop()
	if err := migrate.Up(dsn); err != nil {
		fmt.Fprintf(os.Stderr, "notification: migrate: %v\n", err)
		os.Exit(1)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notification: parse config: %v\n", err)
		os.Exit(1)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	testPool, err = pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notification: pool: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	testPool.Close()
	os.Exit(code)
}

// fakeClock is a deterministic, race-safe clock the tests advance manually.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *fakeClock { return &fakeClock{t: t} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// recordingDeliverer records every delivery and can be told to fail a fixed number
// of times before succeeding (or always).
type recordingDeliverer struct {
	failuresLeft atomic.Int64
	alwaysFail   bool
	delivered    atomic.Int64
}

func (d *recordingDeliverer) Deliver(_ context.Context, _ notification.Notification) error {
	if d.alwaysFail {
		return errors.New("delivery boom")
	}
	if d.failuresLeft.Add(-1) >= 0 {
		return errors.New("transient delivery failure")
	}
	d.delivered.Add(1)
	return nil
}

func uniqueKey(t *testing.T) string { return "test:" + t.Name() }

// clearOutbox empties the shared outbox so a drain test sees only its own rows.
func clearOutbox(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `DELETE FROM notification_outbox`); err != nil {
		t.Fatalf("clear outbox: %v", err)
	}
}

func countRows(t *testing.T, key string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM notification_outbox WHERE idempotency_key = $1`, key).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func rowState(t *testing.T, key string) (state string, attempts int, nextDelivery time.Time) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(),
		`SELECT state, attempts, next_delivery_at FROM notification_outbox WHERE idempotency_key = $1`, key).
		Scan(&state, &attempts, &nextDelivery); err != nil {
		t.Fatalf("row state: %v", err)
	}
	return state, attempts, nextDelivery
}

func TestEnqueueIsTransactional(t *testing.T) {
	ctx := context.Background()
	ob := notification.NewOutbox(testPool, notification.NewLogDeliverer(nil))
	key := uniqueKey(t)

	// Enqueue in a tx that rolls back: nothing durable.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := ob.Enqueue(ctx, sqlc.New(tx), notification.Event{IdempotencyKey: key, Kind: notification.KindIdentityMismatch}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	_ = tx.Rollback(ctx)
	if got := countRows(t, key); got != 0 {
		t.Fatalf("rolled-back enqueue left %d rows, want 0", got)
	}

	// Enqueue in a committed tx: durable.
	tx, err = testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := ob.Enqueue(ctx, sqlc.New(tx), notification.Event{IdempotencyKey: key, Kind: notification.KindIdentityMismatch}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := countRows(t, key); got != 1 {
		t.Fatalf("committed enqueue left %d rows, want 1", got)
	}
}

func TestIdempotencyKeyDedup(t *testing.T) {
	ctx := context.Background()
	ob := notification.NewOutbox(testPool, notification.NewLogDeliverer(nil))
	key := uniqueKey(t)
	for range 3 {
		if err := ob.Enqueue(ctx, sqlc.New(testPool), notification.Event{IdempotencyKey: key, Kind: notification.KindApproachingExpiry}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	if got := countRows(t, key); got != 1 {
		t.Fatalf("dedup left %d rows, want 1", got)
	}
}

func TestDrainDeliversAndMarksDelivered(t *testing.T) {
	ctx := context.Background()
	clearOutbox(t)
	clock := newClock(time.Now().UTC())
	dv := &recordingDeliverer{}
	ob := notification.NewOutbox(testPool, dv, notification.WithClock(clock.now))
	key := uniqueKey(t)
	if err := ob.Enqueue(ctx, sqlc.New(testPool), notification.Event{IdempotencyKey: key, Kind: notification.KindIdentityMismatch, NextDeliveryAt: clock.now()}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	n, err := ob.DrainOnce(ctx, 16)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n == 0 {
		t.Fatalf("drain processed 0 rows, want >= 1")
	}
	if dv.delivered.Load() != 1 {
		t.Fatalf("deliverer saw %d deliveries, want 1", dv.delivered.Load())
	}
	if state, _, _ := rowState(t, key); state != "delivered" {
		t.Fatalf("state = %q, want delivered", state)
	}
	// A second drain must not redeliver a terminal row.
	if _, err := ob.DrainOnce(ctx, 16); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if dv.delivered.Load() != 1 {
		t.Fatalf("terminal row redelivered: %d deliveries", dv.delivered.Load())
	}
}

func TestDrainAtLeastOnceRetriesUntilSuccess(t *testing.T) {
	ctx := context.Background()
	clearOutbox(t)
	clock := newClock(time.Now().UTC())
	dv := &recordingDeliverer{}
	dv.failuresLeft.Store(2) // fail twice, then succeed
	ob := notification.NewOutbox(testPool, dv,
		notification.WithClock(clock.now), notification.WithBackoff(time.Second, time.Minute), notification.WithMaxAttempts(5))
	key := uniqueKey(t)
	if err := ob.Enqueue(ctx, sqlc.New(testPool), notification.Event{IdempotencyKey: key, Kind: notification.KindIdentityMismatch, NextDeliveryAt: clock.now()}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Three drains: fail, fail, succeed. Advance the clock past each backoff.
	for i := range 3 {
		if _, err := ob.DrainOnce(ctx, 16); err != nil {
			t.Fatalf("drain %d: %v", i, err)
		}
		clock.advance(time.Hour) // well past any backoff
	}
	if state, attempts, _ := rowState(t, key); state != "delivered" || attempts != 3 {
		t.Fatalf("state=%q attempts=%d, want delivered/3", state, attempts)
	}
	if dv.delivered.Load() != 1 {
		t.Fatalf("delivered %d times, want exactly 1 success", dv.delivered.Load())
	}
}

func TestBoundedBackoffAndTerminalState(t *testing.T) {
	ctx := context.Background()
	clearOutbox(t)
	start := time.Now().UTC().Truncate(time.Microsecond)
	clock := newClock(start)
	dv := &recordingDeliverer{alwaysFail: true}
	base, ceiling := time.Second, 8*time.Second
	ob := notification.NewOutbox(testPool, dv,
		notification.WithClock(clock.now), notification.WithBackoff(base, ceiling), notification.WithMaxAttempts(4))
	key := uniqueKey(t)
	if err := ob.Enqueue(ctx, sqlc.New(testPool), notification.Event{IdempotencyKey: key, Kind: notification.KindRepeatedProbeFailure, NextDeliveryAt: clock.now()}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	wantBackoff := []time.Duration{base, 2 * base, 4 * base} // 4th attempt goes terminal
	for i, want := range wantBackoff {
		now := clock.now()
		if _, err := ob.DrainOnce(ctx, 16); err != nil {
			t.Fatalf("drain %d never returns an error on delivery failure: %v", i, err)
		}
		state, attempts, next := rowState(t, key)
		if attempts != i+1 {
			t.Fatalf("after drain %d attempts=%d, want %d", i, attempts, i+1)
		}
		if state != "pending" {
			t.Fatalf("after drain %d state=%q, want pending", i, state)
		}
		if got := next.Sub(now); got != want {
			t.Fatalf("after drain %d backoff=%s, want %s (bounded exponential)", i, got, want)
		}
		clock.advance(want) // make it due again
	}
	// Fourth failing drain exhausts the attempt budget → terminal 'failed'.
	if _, err := ob.DrainOnce(ctx, 16); err != nil {
		t.Fatalf("terminal drain: %v", err)
	}
	if state, attempts, _ := rowState(t, key); state != "failed" || attempts != 4 {
		t.Fatalf("state=%q attempts=%d, want failed/4", state, attempts)
	}
	// A failed row is terminal: never selected again.
	clock.advance(time.Hour)
	if _, err := ob.DrainOnce(ctx, 16); err != nil {
		t.Fatalf("post-terminal drain: %v", err)
	}
	if state, attempts, _ := rowState(t, key); state != "failed" || attempts != 4 {
		t.Fatalf("terminal row mutated: state=%q attempts=%d", state, attempts)
	}
}
