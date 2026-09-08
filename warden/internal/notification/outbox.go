// Package notification implements a durable, transactional notification outbox.
//
// Producers enqueue an event inside the transaction that observes the durable
// state it reports (an identity mismatch, repeated probe failure, or approaching
// expiry). A background drainer delivers each event at least once through a
// replaceable adapter, with bounded exponential backoff and a terminal failed
// state after the attempt budget is exhausted. Delivery is strictly best-effort:
// it NEVER reads or mutates authorization or identity state, so a stuck or failing
// outbox can neither block nor weaken enforcement.
package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Notification kinds. Each maps to a distinct operational condition the outbox
// reports; they are the same string values the schema CHECK constraint enforces.
const (
	KindIdentityMismatch     = "identity_mismatch"
	KindRepeatedProbeFailure = "repeated_probe_failure"
	KindApproachingExpiry    = "approaching_expiry"
)

const (
	defaultMaxAttempts = 8
	defaultBaseBackoff = 30 * time.Second
	defaultMaxBackoff  = 1 * time.Hour
	drainBatch         = 128
)

// Event is a notification to enqueue. IdempotencyKey deduplicates producers (a
// re-enqueue with the same key is a no-op) and is the downstream de-dup key.
// Payload must be a canonical JSON object containing only public material
// (identifiers, observed fingerprints) — never secrets.
type Event struct {
	IdempotencyKey string
	Kind           string
	Subject        string
	Payload        []byte
	MaxAttempts    int
	NextDeliveryAt time.Time
}

// Notification is one outbox row handed to a delivery adapter.
type Notification struct {
	ID             string
	IdempotencyKey string
	Kind           string
	Subject        string
	Payload        json.RawMessage
	Attempt        int
}

// Deliverer sends a notification to a destination (log, email, ChatOps, …). A
// non-nil error triggers a bounded-backoff retry; it must be safe to call more
// than once for the same notification (at-least-once delivery).
type Deliverer interface {
	Deliver(ctx context.Context, n Notification) error
}

// LogDeliverer is the first adapter: it emits a structured, redacted log line so
// durable drain is provable without committing to an email/ChatOps vendor. The
// payload carries only public material (identifiers and observed fingerprints),
// so it is logged as-is; no secret ever reaches the outbox.
type LogDeliverer struct{ logger *slog.Logger }

// NewLogDeliverer builds a LogDeliverer over logger (defaults to slog.Default()).
func NewLogDeliverer(logger *slog.Logger) LogDeliverer {
	if logger == nil {
		logger = slog.Default()
	}
	return LogDeliverer{logger: logger}
}

// Deliver logs the notification. It never fails, so the log adapter drains the
// outbox deterministically.
func (d LogDeliverer) Deliver(_ context.Context, n Notification) error {
	d.logger.Info("target identity notification",
		"kind", n.Kind, "subject", n.Subject, "idempotency_key", n.IdempotencyKey,
		"attempt", n.Attempt, "payload", string(n.Payload))
	return nil
}

// Outbox enqueues (transactionally) and drains notifications.
type Outbox struct {
	pool        *pgxpool.Pool
	deliverer   Deliverer
	now         func() time.Time
	maxAttempts int
	baseBackoff time.Duration
	maxBackoff  time.Duration
}

// Option configures an Outbox.
type Option func(*Outbox)

// WithClock overrides the outbox clock, for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(o *Outbox) {
		if now != nil {
			o.now = now
		}
	}
}

// WithBackoff sets the exponential backoff base and ceiling. Non-positive inputs
// are ignored (keep the defaults).
func WithBackoff(base, ceiling time.Duration) Option {
	return func(o *Outbox) {
		if base > 0 {
			o.baseBackoff = base
		}
		if ceiling > 0 {
			o.maxBackoff = ceiling
		}
	}
}

// WithMaxAttempts caps delivery attempts before a notification goes terminal
// (failed). It is the default applied to enqueued events that do not set their own.
func WithMaxAttempts(n int) Option {
	return func(o *Outbox) {
		if n >= 1 {
			o.maxAttempts = n
		}
	}
}

// NewOutbox builds an Outbox over the pool and delivery adapter.
func NewOutbox(pool *pgxpool.Pool, deliverer Deliverer, options ...Option) *Outbox {
	o := &Outbox{
		pool: pool, deliverer: deliverer, now: time.Now,
		maxAttempts: defaultMaxAttempts, baseBackoff: defaultBaseBackoff, maxBackoff: defaultMaxBackoff,
	}
	for _, option := range options {
		if option != nil {
			option(o)
		}
	}
	return o
}

// Enqueue writes an event to the outbox using the CALLER's tx-bound querier, so it
// becomes durable atomically with the state that produced it. A repeat of the same
// idempotency key is a no-op (ON CONFLICT DO NOTHING). Payload defaults to "{}".
func (o *Outbox) Enqueue(ctx context.Context, q *sqlc.Queries, e Event) error {
	if e.IdempotencyKey == "" || e.Kind == "" {
		return errors.New("notification: idempotency key and kind are required")
	}
	payload := e.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	maxAttempts := e.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = o.maxAttempts
	}
	if maxAttempts > math.MaxInt32 {
		maxAttempts = math.MaxInt32
	}
	next := e.NextDeliveryAt
	if next.IsZero() {
		next = o.now()
	}
	if err := q.EnqueueNotification(ctx, sqlc.EnqueueNotificationParams{
		IdempotencyKey: e.IdempotencyKey, Kind: e.Kind, Subject: e.Subject, Payload: payload,
		MaxAttempts: int32(maxAttempts), NextDeliveryAt: pgtype.Timestamptz{Time: next, Valid: true},
	}); err != nil {
		return fmt.Errorf("enqueue notification: %w", err)
	}
	return nil
}

// DrainOnce delivers up to batch due notifications in one transaction. It selects
// pending rows whose next_delivery_at has elapsed (FOR UPDATE SKIP LOCKED, so
// replicas drain disjoint sets), delivers each, and marks it delivered or reschedules
// it with bounded backoff (going terminal at the attempt budget). A delivery error
// is absorbed into the row's retry state — it never fails the drain and never touches
// any other table. Returns the number of rows processed.
//
// ponytail: delivery runs inside the drain tx, holding the row lock. Fine for the
// log adapter (instant); a slow remote adapter should claim-then-deliver-then-ack
// so a network stall does not hold locks — swap the loop body when one lands.
func (o *Outbox) DrainOnce(ctx context.Context, batch int) (int, error) {
	if batch < 1 {
		batch = drainBatch
	}
	now := o.now()
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin drain: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	rows, err := q.ListDueNotifications(ctx, sqlc.ListDueNotificationsParams{
		AtTime: now, Batch: int64(batch),
	})
	if err != nil {
		return 0, fmt.Errorf("list due notifications: %w", err)
	}
	for _, r := range rows {
		n := Notification{
			ID: r.ID.String(), IdempotencyKey: r.IdempotencyKey, Kind: r.Kind,
			Subject: r.Subject, Payload: r.Payload, Attempt: int(r.Attempts) + 1,
		}
		if derr := o.deliverer.Deliver(ctx, n); derr != nil {
			backoff := o.backoff(int(r.Attempts) + 1)
			if err := q.RescheduleNotification(ctx, sqlc.RescheduleNotificationParams{
				LastError:      pgtype.Text{String: truncate(derr.Error(), 500), Valid: true},
				NextDeliveryAt: pgtype.Timestamptz{Time: now.Add(backoff), Valid: true},
				ID:             r.ID,
			}); err != nil {
				return 0, fmt.Errorf("reschedule notification %s: %w", r.ID, err)
			}
			continue
		}
		if err := q.MarkNotificationDelivered(ctx, sqlc.MarkNotificationDeliveredParams{
			DeliveredAt: pgtype.Timestamptz{Time: now, Valid: true}, ID: r.ID,
		}); err != nil {
			return 0, fmt.Errorf("mark delivered %s: %w", r.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit drain: %w", err)
	}
	return len(rows), nil
}

// backoff returns the delay before the next attempt: base * 2^(attempt-1), capped
// at maxBackoff (bounded exponential backoff).
func (o *Outbox) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 62 {
		return o.maxBackoff
	}
	scaled := o.baseBackoff * time.Duration(int64(1)<<uint(shift))
	if scaled <= 0 || scaled > o.maxBackoff || int64(o.baseBackoff) > math.MaxInt64>>uint(shift) {
		return o.maxBackoff
	}
	return scaled
}

// PendingBacklog returns the count of undelivered (pending) notifications, a hook
// for a backlog metric / alert on a wedged drain.
func (o *Outbox) PendingBacklog(ctx context.Context) (int64, error) {
	return sqlc.New(o.pool).CountPendingNotifications(ctx)
}

// Run drains the outbox on a ticker until ctx is cancelled. Each tick drains until
// the due set is empty; a drain error is logged and retried on the next tick.
func (o *Outbox) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := o.DrainOnce(ctx, drainBatch)
				if err != nil {
					if ctx.Err() == nil {
						slog.Error("notification drain failed", "err", err)
					}
					break
				}
				if n < drainBatch {
					break
				}
			}
		}
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
