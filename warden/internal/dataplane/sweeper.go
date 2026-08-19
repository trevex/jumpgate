package dataplane

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
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
	pairs, err := gen.New(s.pool).ListDistinctUserAssetsByWorkers(ctx, workers)
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

const authzChangedChannel = "authz_changed"

// RunAuthzSweeper LISTENs on authz_changed and runs a debounced SweepOwned on each
// notification, plus SweepOwned on a periodic ticker (the pull-sweep backstop).
// Coalesces a burst into a single sweep; at most one sweep runs at a time, with one
// follow-up if a change arrives mid-sweep. Exits on ctx cancellation, waiting for the
// listener goroutine to unwind before returning so callers can safely close the pool.
func (s *Sweeper) RunAuthzSweeper(ctx context.Context, interval, debounce time.Duration) {
	trigger := make(chan struct{}, 1)
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
		case <-trigger:
			t := time.NewTimer(debounce)
			coalesce := true
			for coalesce {
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-trigger:
					if !t.Stop() {
						<-t.C
					}
					t.Reset(debounce)
				case <-t.C:
					coalesce = false
				}
			}
			s.sweepOwnedLogged(ctx)
		}
	}
}

func (s *Sweeper) sweepOwnedLogged(ctx context.Context) {
	if err := s.SweepOwned(ctx); err != nil && ctx.Err() == nil {
		slog.Error("authz sweep failed", "err", err)
	}
}

func (s *Sweeper) listenAuthz(ctx context.Context, trigger chan<- struct{}) {
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

func (s *Sweeper) listenAuthzLoop(ctx context.Context, trigger chan<- struct{}) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+authzChangedChannel); err != nil {
		return err
	}
	select {
	case trigger <- struct{}{}:
	default:
	}
	for {
		if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
			return err
		}
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
}
