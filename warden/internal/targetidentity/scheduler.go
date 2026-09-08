package targetidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/notification"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

const (
	defaultFailureThreshold = 3
	defaultExpiryWarn       = 24 * time.Hour
	defaultConcurrency      = 32
)

// Notifier is the transactional notification-enqueue capability the scheduler
// needs. *notification.Outbox satisfies it; the interface keeps the scheduler
// testable and the outbox implementation replaceable.
type Notifier interface {
	Enqueue(ctx context.Context, q *sqlc.Queries, e notification.Event) error
}

// Scheduler drives continuous target-identity monitoring. On each tick it queues
// due periodic probes for opted-in assets (jittered, DB-time due selection, bounded
// by a global concurrency cap) and enqueues durable notifications for identity
// mismatch, repeated probe failure, and approaching expiry. It NEVER changes trust:
// a failed probe queues a degraded-connectivity notification, not a revocation.
//
// Periodic probing is disabled by default — with no enabled schedule rows the
// scheduler queues nothing — and the reused ProbeDispatcher (Task 4) still executes
// the queued jobs; the scheduler only decides WHEN to queue them.
type Scheduler struct {
	pool             *pgxpool.Pool
	svc              *Service
	notifier         Notifier
	interval         time.Duration
	jitter           time.Duration
	concurrency      int
	failureThreshold int
	expiryWarn       time.Duration
	now              func() time.Time
	randFloat        func() float64
}

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithSchedulerClock overrides the scheduler clock (deterministic tests).
func WithSchedulerClock(now func() time.Time) SchedulerOption {
	return func(s *Scheduler) {
		if now != nil {
			s.now = now
		}
	}
}

// WithJitterSource injects the randomness used for probe jitter. randFloat must
// return a value in [0,1); the jitter added to a queued probe is randFloat()*jitter,
// so it always stays within [0, jitter). Tests inject a deterministic source.
func WithJitterSource(randFloat func() float64) SchedulerOption {
	return func(s *Scheduler) {
		if randFloat != nil {
			s.randFloat = randFloat
		}
	}
}

// WithFailureThreshold sets how many failed probes since the last success trigger a
// repeated-probe-failure notification. Non-positive input keeps the default.
func WithFailureThreshold(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n > 0 {
			s.failureThreshold = n
		}
	}
}

// WithExpiryWarn sets the look-ahead window for approaching-expiry notifications.
// Non-positive input keeps the default.
func WithExpiryWarn(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.expiryWarn = d
		}
	}
}

// NewScheduler builds a Scheduler. interval is the tick period; jitter bounds the
// random delay spread over queued probes; concurrency caps probes queued per tick.
func NewScheduler(pool *pgxpool.Pool, svc *Service, notifier Notifier, interval, jitter time.Duration, concurrency int, options ...SchedulerOption) *Scheduler {
	if concurrency < 1 {
		concurrency = defaultConcurrency
	}
	s := &Scheduler{
		pool: pool, svc: svc, notifier: notifier,
		interval: interval, jitter: jitter, concurrency: concurrency,
		failureThreshold: defaultFailureThreshold, expiryWarn: defaultExpiryWarn,
		now: time.Now, randFloat: rand.Float64,
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	return s
}

// Tick runs one scheduling pass: queue due periodic probes, then enqueue any
// operational notifications. Errors from either half are returned joined; neither
// half's failure blocks the other.
func (s *Scheduler) Tick(ctx context.Context) error {
	queueErr := s.QueueDueProbes(ctx)
	notifyErr := s.EnqueueNotifications(ctx)
	return errors.Join(queueErr, notifyErr)
}

// QueueDueProbes queues a jittered periodic probe for each opted-in asset whose
// interval has elapsed, up to the concurrency cap, in a single transaction. Due
// selection uses the scheduler clock as the reference time evaluated in SQL against
// each asset's interval (database-side interval arithmetic), and FOR UPDATE SKIP
// LOCKED partitions due assets across replicas. The partial unique index is the
// correctness backstop: a duplicate current-revision periodic job cannot be created.
func (s *Scheduler) QueueDueProbes(ctx context.Context) error {
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin queue due probes: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	due, err := q.ListDuePeriodicProbes(ctx, sqlc.ListDuePeriodicProbesParams{AtTime: now, Batch: int64(s.concurrency)})
	if err != nil {
		return fmt.Errorf("list due periodic probes: %w", err)
	}
	for _, d := range due {
		if _, err := s.svc.QueueProbeTx(ctx, q, QueueProbeRequest{
			AssetID:          d.AssetID,
			EndpointRevision: d.EndpointRevision,
			Reason:           ProbeReasonPeriodic,
			NextAttemptAt:    now.Add(s.jitterDelay()),
		}); err != nil {
			// Both are benign, per-row conditions that must not abort the batch (a
			// rolled-back tick would let one churning asset starve every other due
			// asset). ErrProbeAlreadyQueued: another producer already queued it.
			// ErrStaleRevision: the asset's endpoint_revision moved between the due
			// SELECT and QueueProbeTx's locked re-read, so this due row is stale — the
			// asset re-probes at its new revision next tick.
			if errors.Is(err, ErrProbeAlreadyQueued) || errors.Is(err, ErrStaleRevision) {
				continue
			}
			return fmt.Errorf("queue periodic probe for asset %s: %w", d.AssetID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit queue due probes: %w", err)
	}
	return nil
}

// jitterDelay returns a random delay in [0, jitter) added to a queued probe's next
// attempt so probes do not fire in lockstep. A zero jitter yields zero delay.
func (s *Scheduler) jitterDelay() time.Duration {
	if s.jitter <= 0 {
		return 0
	}
	f := s.randFloat()
	if f < 0 {
		f = 0
	}
	if f >= 1 {
		f = 0.999999
	}
	return time.Duration(f * float64(s.jitter))
}

// EnqueueNotifications scans durable state for the three notification conditions
// and enqueues one event per condition, transactionally. Each event carries a
// stable idempotency key so re-scans do not duplicate delivery (ON CONFLICT DO
// NOTHING). Payloads contain only public material.
func (s *Scheduler) EnqueueNotifications(ctx context.Context) error {
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enqueue notifications: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	mismatches, err := q.ListUnresolvedMismatches(ctx, now)
	if err != nil {
		return fmt.Errorf("list unresolved mismatches: %w", err)
	}
	for _, m := range mismatches {
		if err := s.enqueue(ctx, q, now, notification.KindIdentityMismatch,
			"mismatch:"+m.ObservationID.String(), m.AssetID.String(), map[string]any{
				"asset_id": m.AssetID.String(), "endpoint_revision": m.EndpointRevision,
				"observation_id": m.ObservationID.String(),
			}); err != nil {
			return err
		}
	}

	failures, err := q.ListRepeatedProbeFailures(ctx, int64(s.failureThreshold))
	if err != nil {
		return fmt.Errorf("list repeated probe failures: %w", err)
	}
	for _, f := range failures {
		// Key on the latest failed job id (not the asset): each NEW failed probe past
		// the threshold mints a fresh notification — one alert per new failure, not
		// one per degraded episode. Intended and bounded by probe cadence, not a dedup bug.
		if err := s.enqueue(ctx, q, now, notification.KindRepeatedProbeFailure,
			"probe_failure:"+f.LatestFailedJobID.String(), f.AssetID.String(), map[string]any{
				"asset_id": f.AssetID.String(), "endpoint_revision": f.EndpointRevision,
				"failure_count": f.FailureCount, "latest_failed_job_id": f.LatestFailedJobID.String(),
			}); err != nil {
			return err
		}
	}

	warnSeconds := int64(s.expiryWarn / time.Second)
	anchorExpiry, err := q.ListApproachingAnchorExpiry(ctx, sqlc.ListApproachingAnchorExpiryParams{AtTime: now, WarnSeconds: warnSeconds})
	if err != nil {
		return fmt.Errorf("list approaching anchor expiry: %w", err)
	}
	for _, a := range anchorExpiry {
		if err := s.enqueue(ctx, q, now, notification.KindApproachingExpiry,
			"anchor_expiry:"+a.AnchorID.String(), a.AssetID.String(), map[string]any{
				"asset_id": a.AssetID.String(), "endpoint_revision": a.EndpointRevision,
				"anchor_id": a.AnchorID.String(), "expires_at": a.ExpiresAt.Time.UTC().Format(time.RFC3339),
				"reason": "anchor",
			}); err != nil {
			return err
		}
	}

	freshnessExpiry, err := q.ListApproachingFreshnessExpiry(ctx, sqlc.ListApproachingFreshnessExpiryParams{AtTime: now, WarnSeconds: warnSeconds})
	if err != nil {
		return fmt.Errorf("list approaching freshness expiry: %w", err)
	}
	for _, f := range freshnessExpiry {
		expiresAt := f.ExpiresAt.UTC().Format(time.RFC3339)
		if err := s.enqueue(ctx, q, now, notification.KindApproachingExpiry,
			fmt.Sprintf("freshness_expiry:%s:%d:%s", f.AssetID, f.EndpointRevision, expiresAt), f.AssetID.String(), map[string]any{
				"asset_id": f.AssetID.String(), "endpoint_revision": f.EndpointRevision,
				"expires_at": expiresAt, "reason": "freshness",
			}); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enqueue notifications: %w", err)
	}
	return nil
}

func (s *Scheduler) enqueue(ctx context.Context, q *sqlc.Queries, now time.Time, kind, key, subject string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal notification payload: %w", err)
	}
	if err := s.notifier.Enqueue(ctx, q, notification.Event{
		IdempotencyKey: key, Kind: kind, Subject: "asset:" + subject, Payload: raw, NextDeliveryAt: now,
	}); err != nil {
		return fmt.Errorf("enqueue %s notification: %w", kind, err)
	}
	return nil
}

// Run drives Tick on a ticker until ctx is cancelled. A tick error is logged and
// retried on the next tick; it never blocks the loop.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
				slog.Error("target identity scheduler tick failed", "err", err)
			}
		}
	}
}
