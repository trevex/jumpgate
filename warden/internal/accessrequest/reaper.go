package accessrequest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ReapExpired marks every grant whose window has elapsed as revoked
// (revoked_reason='expired') and, in the same transaction, enqueues an
// access_grant.expired audit event for each into the outbox — so the expiry and
// its audit trail commit atomically (an enqueue failure rolls back the whole
// sweep). After commit it notifies the terminator per grant so any live sessions
// are torn down; the terminator is best-effort and logged on failure (a single
// terminator error must not abort the post-commit teardown loop). Returns the
// number of grants expired.
//
// Authorization already treats expired grants as inactive (the held-closure filters
// expires_at > now()); this reaper is a SIDE-EFFECTS job (audit + teardown), not an
// authz-correctness requirement. It is idempotent: ExpireGrants excludes rows with
// revoked_at already set, so a re-run over the same window returns 0.
func (s *Service) ReapExpired(ctx context.Context) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	expired, err := q.ExpireGrants(ctx)
	if err != nil {
		return 0, err
	}
	for _, g := range expired {
		if err := s.enqueueExpired(ctx, q, g); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	for _, g := range expired {
		s.terminate(ctx, g.ID)
	}
	return len(expired), nil
}

// RunReaper runs ReapExpired on a ticker until ctx is cancelled (graceful
// shutdown). Mirrors the token-GC goroutine in main.go.
func (s *Service) RunReaper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.ReapExpired(ctx); err != nil {
				slog.Error("reaper failed", "err", err)
			} else if n > 0 {
				slog.Info("reaped expired grants", "count", n)
			}
		}
	}
}

// enqueueExpired writes the grant-expiry audit event into the outbox on the
// caller's tx-bound querier (atomic with the expiry write). The actor is the
// system (uuid.Nil): expiry is time-driven, with no human actor.
func (s *Service) enqueueExpired(ctx context.Context, q *sqlc.Queries, g sqlc.AccessGrant) error {
	if s.audit == nil {
		return nil
	}
	details := map[string]any{
		"grant_id":   g.ID.String(),
		"request_id": g.RequestID.String(),
		"role_id":    g.RoleID.String(),
		"asset_id":   g.ScopeAssetID.String(),
		"subject":    g.SubjectUserID.String(),
	}
	raw, _ := json.Marshal(details)
	return s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventGrantExpired,
		ActorID: uuid.Nil,
		Subject: "access_grant:" + g.ID.String(),
		Details: raw,
	})
}
