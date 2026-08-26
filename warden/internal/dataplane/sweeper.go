package dataplane

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Sweeper re-evaluates the connect predicate for live sessions and tears down those
// that lost their standing login. It complements the event-driven grant teardown by
// reconciling on authorization changes that are not tied to a single grant (e.g. a
// removed role binding, group membership, or role rewrite) and as a periodic backstop
// against missed notifications.
//
// Work is partitioned by ownership: each replica only sweeps sessions whose worker is
// connected to it, so the sweep cost scales with local fan-out and never duplicates
// teardown work across replicas.
type Sweeper struct {
	pool       *pgxpool.Pool
	registry   *Registry
	terminator *Terminator
}

// NewSweeper builds a Sweeper over the pool, the local worker registry, and the
// terminator that performs the actual re-evaluation and teardown.
func NewSweeper(pool *pgxpool.Pool, registry *Registry, terminator *Terminator) *Sweeper {
	return &Sweeper{pool: pool, registry: registry, terminator: terminator}
}

// SweepOwned re-evaluates the connect predicate for every live session whose worker
// is connected to this replica, tearing down those that lost their login. Sessions
// owned by other replicas (or no replica) are skipped here.
func (s *Sweeper) SweepOwned(ctx context.Context) error {
	workers := s.registry.ConnectedWorkers()
	if len(workers) == 0 {
		return nil
	}
	pairs, err := sqlc.New(s.pool).ListDistinctUserAssetsByWorkers(ctx, workers)
	if err != nil {
		return fmt.Errorf("list owned sessions: %w", err)
	}
	for _, p := range pairs {
		if err := s.terminator.Reevaluate(ctx, p.UserID, p.AssetID); err != nil {
			slog.Error("sweep reevaluate failed", "user", p.UserID, "asset", p.AssetID, "err", err)
		}
	}
	return nil
}

// SweepOwnedForUser is the narrowed sweep: it re-evaluates the connect predicate for
// only the given user's live sessions whose worker is connected to this replica, and
// tears down those that lost their login. It restricts WHICH (user,asset) pairs are
// evaluated but uses the SAME per-pair Terminator.Reevaluate as SweepOwned — never a
// different teardown decision. Used when an authz_changed notification identifies a
// single affected user (see the always-safe-to-full-sweep invariant in the trigger).
func (s *Sweeper) SweepOwnedForUser(ctx context.Context, userID uuid.UUID) error {
	workers := s.registry.ConnectedWorkers()
	if len(workers) == 0 {
		return nil
	}
	assets, err := sqlc.New(s.pool).ListDistinctAssetsByUserAndWorkers(ctx, sqlc.ListDistinctAssetsByUserAndWorkersParams{
		UserID:  userID,
		Column2: workers,
	})
	if err != nil {
		return fmt.Errorf("list owned sessions for user: %w", err)
	}
	for _, assetID := range assets {
		if err := s.terminator.Reevaluate(ctx, userID, assetID); err != nil {
			slog.Error("sweep reevaluate failed", "user", userID, "asset", assetID, "err", err)
		}
	}
	return nil
}

// SweepGC reconciles the live_sessions ledger with reality: it force-cleans sessions
// whose worker has gone unreachable (presence older than orphanGrace) and sessions
// stuck marked-terminating past teardownGrace, then prunes dead worker_presence rows.
// MarkEnded is idempotent (its delete is :execrows), so running this on every replica
// concurrently produces no duplicate audit events.
func (s *Sweeper) SweepGC(ctx context.Context, orphanGrace, teardownGrace time.Duration) error {
	q := sqlc.New(s.pool)
	now := time.Now()

	orphanCutoff := pgtype.Timestamptz{Time: now.Add(-orphanGrace), Valid: true}
	orphans, err := q.ListStaleWorkerSessions(ctx, orphanCutoff)
	if err != nil {
		return fmt.Errorf("list stale sessions: %w", err)
	}
	for _, id := range orphans {
		if err := s.terminator.MarkEnded(ctx, id, "worker unreachable"); err != nil {
			slog.Error("orphan gc mark-ended failed", "session", id, "err", err)
		}
	}

	stuckCutoff := pgtype.Timestamptz{Time: now.Add(-teardownGrace), Valid: true}
	stuck, err := q.ListStuckTerminatingSessions(ctx, stuckCutoff)
	if err != nil {
		return fmt.Errorf("list stuck sessions: %w", err)
	}
	for _, id := range stuck {
		if err := s.terminator.MarkEnded(ctx, id, "teardown unconfirmed"); err != nil {
			slog.Error("stuck gc mark-ended failed", "session", id, "err", err)
		}
	}

	if err := q.DeleteStaleWorkerPresence(ctx, orphanCutoff); err != nil {
		slog.Error("prune stale presence failed", "err", err)
	}
	return nil
}

// RunGC runs SweepGC on a ticker until ctx is cancelled.
func (s *Sweeper) RunGC(ctx context.Context, interval, orphanGrace, teardownGrace time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SweepGC(ctx, orphanGrace, teardownGrace); err != nil && ctx.Err() == nil {
				slog.Error("gc sweep failed", "err", err)
			}
		}
	}
}

const listenAuthzChangedSQL = "LISTEN authz_changed"

// RunAuthzSweeper LISTENs on authz_changed and runs a debounced sweep on each
// notification, plus a full SweepOwned on a periodic ticker (the pull-sweep backstop).
//
// The notification payload identifies the affected subject: an empty payload means a
// full sweep is required (the change had a transitive/broad blast radius); a payload
// that parses as a user UUID means only that user's sessions need re-evaluation.
//
// A burst is coalesced into a single sweep over the debounce window. The window
// accumulates the union of specific affected users, BUT if ANY empty-payload (or any
// unparseable payload) arrives, the whole batch escalates to a full sweep — a full
// sweep supersedes any set of narrow ones, so this is always at least as much work as
// each narrow sweep would have done (never less). At most one sweep runs at a time,
// with one follow-up if a change arrives mid-sweep. Exits on ctx cancellation, waiting
// for the listener goroutine to unwind before returning so callers can safely close
// the pool.
func (s *Sweeper) RunAuthzSweeper(ctx context.Context, interval, debounce time.Duration) {
	trigger := make(chan string, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.listenAuthz(ctx, trigger)
	}()
	defer wg.Wait()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepOwnedLogged(ctx)
		case payload := <-trigger:
			full, users := s.accumulate(false, nil, payload)
			t := time.NewTimer(debounce)
			coalesce := true
			for coalesce {
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case p := <-trigger:
					full, users = s.accumulate(full, users, p)
					if !t.Stop() {
						<-t.C
					}
					t.Reset(debounce)
				case <-t.C:
					coalesce = false
				}
			}
			s.runBatch(ctx, full, users)
		}
	}
}

// accumulate folds one notification payload into the running batch state (full,users)
// and returns the updated state. Escalation is MONOTONIC within a debounce window: once
// full is true it stays true — a full sweep supersedes any narrow ones, so an already-
// escalated batch is never downgraded by a subsequent specific-user payload, regardless
// of arrival order. An empty or unparseable payload escalates to a full sweep (the
// always-safe fallback); a parseable user UUID adds that user to the narrow set. When
// full, the narrow user set is cleared/ignored — runBatch does one full sweep instead.
func (s *Sweeper) accumulate(full bool, users map[uuid.UUID]struct{}, payload string) (bool, map[uuid.UUID]struct{}) {
	if full {
		// Already escalated; specifics are irrelevant and a full sweep covers them.
		return true, nil
	}
	if payload == "" {
		return true, nil
	}
	id, err := uuid.Parse(payload)
	if err != nil {
		// Unrecognized payload: fail safe to a full sweep.
		return true, nil
	}
	if users == nil {
		users = make(map[uuid.UUID]struct{})
	}
	users[id] = struct{}{}
	return false, users
}

// runBatch executes the coalesced sweep: a full SweepOwned if required, otherwise a
// narrowed SweepOwnedForUser per accumulated user. An empty batch (no users, not full)
// cannot happen — the loop is only entered after at least one payload is accumulated.
func (s *Sweeper) runBatch(ctx context.Context, full bool, users map[uuid.UUID]struct{}) {
	if full || len(users) == 0 {
		s.sweepOwnedLogged(ctx)
		return
	}
	for id := range users {
		if err := s.SweepOwnedForUser(ctx, id); err != nil && ctx.Err() == nil {
			slog.Error("authz sweep for user failed", "user", id, "err", err)
		}
	}
}

func (s *Sweeper) sweepOwnedLogged(ctx context.Context) {
	if err := s.SweepOwned(ctx); err != nil && ctx.Err() == nil {
		slog.Error("authz sweep failed", "err", err)
	}
}

func (s *Sweeper) listenAuthz(ctx context.Context, trigger chan<- string) {
	for ctx.Err() == nil {
		if err := s.listenAuthzLoop(ctx, trigger); err != nil && ctx.Err() == nil {
			slog.Error("authz listener error; retrying", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

func (s *Sweeper) listenAuthzLoop(ctx context.Context, trigger chan<- string) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, listenAuthzChangedSQL); err != nil {
		return err
	}
	// On (re)connect, force a full sweep to reconcile anything missed while detached.
	sendTrigger(ctx, trigger, "")
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		sendTrigger(ctx, trigger, n.Payload)
	}
}

// sendTrigger delivers a payload to the debounce loop. The channel is buffered; if it
// is momentarily full (a large burst faster than the loop drains), block briefly rather
// than drop — dropping a specific-user payload while keeping others could miss a user.
// Coalescing still happens in the debounce window; this only bounds memory. On ctx
// cancel it gives up (the loop is exiting anyway).
func sendTrigger(ctx context.Context, trigger chan<- string, payload string) {
	select {
	case trigger <- payload:
	default:
		select {
		case trigger <- payload:
		case <-ctx.Done():
		}
	}
}
