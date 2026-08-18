package accessrequest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// ReapExpired marks every grant whose window has elapsed as revoked
// (revoked_reason='expired'), then for each such grant audits access_grant.expired
// and notifies the terminator so any live sessions are torn down. Both side effects
// are best-effort and logged on failure — a single audit/terminator error must not
// abort the sweep. Returns the number of grants expired.
//
// Authorization already treats expired grants as inactive (the held-closure filters
// expires_at > now()); this reaper is a SIDE-EFFECTS job (audit + teardown), not an
// authz-correctness requirement. It is idempotent: ExpireGrants excludes rows with
// revoked_at already set, so a re-run over the same window returns 0.
func (s *Service) ReapExpired(ctx context.Context) (int, error) {
	expired, err := gen.New(s.pool).ExpireGrants(ctx)
	if err != nil {
		return 0, err
	}
	for _, g := range expired {
		s.appendExpired(ctx, g)
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

// appendExpired writes the grant-expiry audit event (best-effort). The actor is the
// system (uuid.Nil): expiry is time-driven, with no human actor.
func (s *Service) appendExpired(ctx context.Context, g gen.AccessGrant) {
	if s.audit == nil {
		return
	}
	details := map[string]any{
		"grant_id":   g.ID.String(),
		"request_id": g.RequestID.String(),
		"role_id":    g.RoleID.String(),
		"asset_id":   g.ScopeAssetID.String(),
		"subject":    g.SubjectUserID.String(),
	}
	raw, _ := json.Marshal(details)
	if err := s.audit.Append(ctx, audit.Event{
		Type:    EventGrantExpired,
		ActorID: uuid.Nil,
		Subject: "access_grant:" + g.ID.String(),
		Details: raw,
	}); err != nil {
		slog.Error("audit append failed", "event", EventGrantExpired, "grant_id", g.ID.String(), "err", err)
	}
}
