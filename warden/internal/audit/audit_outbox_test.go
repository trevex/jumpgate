package audit_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// enqueueCommit enqueues one event inside its own committed transaction, mirroring
// how a domain service enqueues inside its domain tx (Enqueue rides the caller's
// tx-bound querier; the outbox row is durable on commit).
func enqueueCommit(t *testing.T, pool *pgxpool.Pool, log *audit.Logger, e audit.Event) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := log.Enqueue(ctx, sqlc.New(tx), e); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func countOutbox(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	n, err := sqlc.New(pool).CountOutbox(context.Background())
	if err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

func countChain(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	rows, err := sqlc.New(pool).ListAuditEntries(context.Background())
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	return len(rows)
}

// TestEnqueueGoesToOutboxNotChain: Enqueue in a committed tx writes to the outbox
// but NOT into the hash chain (the drainer is what chains it).
func TestEnqueueGoesToOutboxNotChain(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	enqueueCommit(t, pool, log, audit.Event{Type: "t.x", Subject: "s", Details: []byte(`{"k":1}`)})

	if got := countOutbox(t, pool); got != 1 {
		t.Fatalf("outbox count = %d, want 1", got)
	}
	if got := countChain(t, pool); got != 0 {
		t.Fatalf("chain count = %d, want 0 (nothing drained yet)", got)
	}
	// An empty chain verifies trivially.
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify empty chain: %v", err)
	}
}

// TestDrainOnceChainsEmptiesVerifies: DrainOnce chains the outbox row, empties the
// outbox, and the resulting chain verifies.
func TestDrainOnceChainsEmptiesVerifies(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	enqueueCommit(t, pool, log, audit.Event{Type: "t.x", Subject: "s", Details: []byte(`{"k":1}`)})

	n, err := log.DrainOnce(ctx, 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("drained = %d, want 1", n)
	}
	if got := countChain(t, pool); got != 1 {
		t.Fatalf("chain count = %d, want 1", got)
	}
	if got := countOutbox(t, pool); got != 0 {
		t.Fatalf("outbox count = %d, want 0", got)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestDrainPreservesSeqOrder: three events enqueued in seq order land in the chain
// in that same order.
func TestDrainPreservesSeqOrder(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	enqueueCommit(t, pool, log, audit.Event{Type: "t.1", Subject: "s1"})
	enqueueCommit(t, pool, log, audit.Event{Type: "t.2", Subject: "s2"})
	enqueueCommit(t, pool, log, audit.Event{Type: "t.3", Subject: "s3"})

	n, err := log.DrainOnce(ctx, 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 3 {
		t.Fatalf("drained = %d, want 3", n)
	}
	rows, err := sqlc.New(pool).ListAuditEntries(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"t.1", "t.2", "t.3"}
	if len(rows) != len(want) {
		t.Fatalf("chain len = %d, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if rows[i].EventType != w {
			t.Fatalf("chain[%d] = %q, want %q", i, rows[i].EventType, w)
		}
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestOutboxDurabilityAcrossCrash: an enqueued event survives (durable in outbox,
// absent from the chain) when the process would crash before draining; a later
// DrainOnce recovers it into the chain. This proves the outbox closes the
// post-commit crash window.
func TestOutboxDurabilityAcrossCrash(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	enqueueCommit(t, pool, log, audit.Event{Type: "t.durable", Subject: "s", Details: []byte(`{"k":2}`)})

	// Simulated crash: the drainer never ran. The event must be durable in the
	// outbox and NOT yet in the chain.
	if got := countOutbox(t, pool); got != 1 {
		t.Fatalf("outbox count = %d, want 1 (durable across crash)", got)
	}
	if got := countChain(t, pool); got != 0 {
		t.Fatalf("chain count = %d, want 0 (not yet chained)", got)
	}

	// Recovery: the drainer catches up after restart.
	n, err := log.DrainOnce(ctx, 10)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("drained = %d, want 1", n)
	}
	if got := countChain(t, pool); got != 1 {
		t.Fatalf("chain count = %d, want 1 after recovery", got)
	}
	if got := countOutbox(t, pool); got != 0 {
		t.Fatalf("outbox count = %d, want 0 after recovery", got)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestDrainExactlyOnce: a second DrainOnce after everything is drained returns 0
// and leaves the chain unchanged (each event chained exactly once).
func TestDrainExactlyOnce(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	enqueueCommit(t, pool, log, audit.Event{Type: "t.once", Subject: "s"})

	if n, err := log.DrainOnce(ctx, 10); err != nil || n != 1 {
		t.Fatalf("first drain: n=%d err=%v", n, err)
	}
	before := countChain(t, pool)

	n, err := log.DrainOnce(ctx, 10)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if n != 0 {
		t.Fatalf("second drain drained = %d, want 0", n)
	}
	if after := countChain(t, pool); after != before {
		t.Fatalf("chain changed on empty drain: before=%d after=%d", before, after)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestAppendAndDrainInterleave: a direct Append and a drained enqueued event both
// land in the chain and it verifies — the advisory lock serializes the two paths.
func TestAppendAndDrainInterleave(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	if err := log.Append(ctx, audit.Event{Type: "t.direct", Subject: "s0"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	enqueueCommit(t, pool, log, audit.Event{Type: "t.enqueued", Subject: "s1"})

	if n, err := log.DrainOnce(ctx, 10); err != nil || n != 1 {
		t.Fatalf("drain: n=%d err=%v", n, err)
	}
	if got := countChain(t, pool); got != 2 {
		t.Fatalf("chain count = %d, want 2", got)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
