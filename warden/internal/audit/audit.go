// Package audit implements a hash-chained, tamper-evident audit log.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Event is an audit event to append.
type Event struct {
	Type    string
	ActorID uuid.UUID // uuid.Nil for system/no actor
	Subject string
	Details []byte // canonical JSON; pass []byte("{}") if none
}

// Logger appends tamper-evident entries and verifies the chain.
type Logger struct {
	pool *pgxpool.Pool
}

// New constructs a Logger.
func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// computeHash returns sha256(prevHash || len-prefixed canonical fields).
// The length prefix uses big-endian uint64 to prevent field boundary ambiguity.
func computeHash(prevHash []byte, e Event) []byte {
	h := sha256.New()
	h.Write(prevHash)
	writeField := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeField([]byte(e.Type))
	actor := ""
	if e.ActorID != uuid.Nil {
		actor = e.ActorID.String()
	}
	writeField([]byte(actor))
	writeField([]byte(e.Subject))
	writeField(e.Details)
	return h.Sum(nil)
}

// Append writes one entry, chaining from the current tail. An advisory lock
// serializes all appends (including concurrent first-inserts) so the genesis
// entry can only be created once even when the table is empty (FOR UPDATE
// cannot lock a row that does not exist).
func (l *Logger) Append(ctx context.Context, e Event) error {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)

	if err := q.AcquireAuditLock(ctx); err != nil {
		return fmt.Errorf("acquire audit lock: %w", err)
	}
	if err := l.appendLocked(ctx, q, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// appendLocked chains one entry onto the tail using the given tx-bound querier.
// The caller MUST already hold the audit advisory lock on q's tx (via
// AcquireAuditLock) and is responsible for begin/commit. This is the shared core
// of Append and DrainOnce: it normalizes details, locks the tail for the prev
// hash, computes the entry hash, and inserts — but never touches the tx lifecycle
// or the lock, so multiple entries can be chained within one locked tx (drain).
func (l *Logger) appendLocked(ctx context.Context, q *gen.Queries, e Event) error {
	if e.Details == nil {
		e.Details = []byte("{}")
	}

	// Normalize details via postgres so the hashed bytes match what is stored.
	normalized, err := q.NormalizeJSON(ctx, e.Details)
	if err != nil {
		return fmt.Errorf("normalize details: %w", err)
	}
	e.Details = normalized

	prev, err := q.LockLastAuditEntry(ctx)
	prevHash := make([]byte, 32) // genesis prev = 32 zero bytes
	if err == nil {
		prevHash = prev
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lock tail: %w", err)
	}

	entryHash := computeHash(prevHash, e)
	var actor pgtype.UUID
	if e.ActorID != uuid.Nil {
		actor = pgtype.UUID{Bytes: e.ActorID, Valid: true}
	}
	if _, err := q.InsertAuditEntry(ctx, gen.InsertAuditEntryParams{
		EventType:   e.Type,
		ActorUserID: actor,
		Subject:     e.Subject,
		Details:     e.Details,
		PrevHash:    prevHash,
		EntryHash:   entryHash,
	}); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

// Enqueue writes an audit event to the transactional outbox using the CALLER's
// tx-bound querier. Because the insert rides in the caller's domain transaction,
// the event becomes durable ATOMICALLY with the action it records: either both
// commit or neither does, closing the post-commit crash window that a direct
// Append (which opens its own tx) leaves open. This is a plain insert — no
// advisory lock, no hashing — the drainer (DrainOnce) later moves the row into
// the hash-chained audit_log in seq order.
func (l *Logger) Enqueue(ctx context.Context, q *gen.Queries, e Event) error {
	details := e.Details
	if details == nil {
		details = []byte("{}")
	}
	var actor pgtype.UUID
	if e.ActorID != uuid.Nil {
		actor = pgtype.UUID{Bytes: e.ActorID, Valid: true}
	}
	if _, err := q.EnqueueAuditEvent(ctx, gen.EnqueueAuditEventParams{
		EventType:   e.Type,
		ActorUserID: actor,
		Subject:     e.Subject,
		Details:     details,
	}); err != nil {
		return fmt.Errorf("enqueue: %w", err)
	}
	return nil
}

// DrainOnce moves up to batch outbox rows into the hash-chained audit_log in one
// transaction. It acquires the audit advisory lock (serializing against Append
// and other drains), reads the oldest undrained rows in seq order, and for each
// row chains it (appendLocked) THEN deletes it — both within the same tx. Because
// the chain-insert and the outbox delete commit together, each event is chained
// EXACTLY once and in seq order; a crash before commit rolls back both, so the
// row is simply re-drained on the next call (at-least-once delivery + the delete
// making it effectively exactly-once). Returns the number of events chained.
func (l *Logger) DrainOnce(ctx context.Context, batch int) (int, error) {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)

	if err := q.AcquireAuditLock(ctx); err != nil {
		return 0, fmt.Errorf("acquire audit lock: %w", err)
	}

	limit := batch
	if limit < 0 || limit > math.MaxInt32 {
		limit = math.MaxInt32
	}
	rows, err := q.ListUndrainedOutbox(ctx, int32(limit))
	if err != nil {
		return 0, fmt.Errorf("list outbox: %w", err)
	}
	for _, r := range rows {
		actor := uuid.Nil
		if r.ActorUserID.Valid {
			actor = uuid.UUID(r.ActorUserID.Bytes)
		}
		if err := l.appendLocked(ctx, q, Event{
			Type:    r.EventType,
			ActorID: actor,
			Subject: r.Subject,
			Details: r.Details,
		}); err != nil {
			return 0, fmt.Errorf("chain outbox %s: %w", r.ID, err)
		}
		if err := q.DeleteOutboxEvent(ctx, r.ID); err != nil {
			return 0, fmt.Errorf("delete outbox %s: %w", r.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return len(rows), nil
}

// RunDrainer drains the audit outbox into the hash chain on a ticker until ctx is
// cancelled (graceful shutdown). Each tick drains until the outbox is empty (a
// backlog is cleared promptly rather than one batch per interval); a drain error
// is logged and retried on the next tick. Mirrors the reaper goroutine's shape.
func (l *Logger) RunDrainer(ctx context.Context, interval time.Duration) {
	const batch = 256
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := l.DrainOnce(ctx, batch)
				if err != nil {
					slog.Error("audit drain failed", "err", err)
					break
				}
				if n < batch {
					break // fully drained (or nothing to do)
				}
			}
		}
	}
}

// Verify recomputes the whole chain and returns an error at the first mismatch.
// It detects mutation, reordering, and middle-row deletion of committed entries,
// but cannot detect truncation of the most-recent entries (a shorter valid chain
// is indistinguishable from the full chain). Detecting tail truncation requires
// anchoring the chain tip in an external store — a later milestone.
func (l *Logger) Verify(ctx context.Context) error {
	rows, err := gen.New(l.pool).ListAuditEntries(ctx)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	prevHash := make([]byte, 32)
	for i, r := range rows {
		actor := uuid.Nil
		if r.ActorUserID.Valid {
			actor = uuid.UUID(r.ActorUserID.Bytes)
		}
		want := computeHash(prevHash, Event{
			Type:    r.EventType,
			ActorID: actor,
			Subject: r.Subject,
			Details: r.Details,
		})
		if !bytes.Equal(want, r.EntryHash) {
			return fmt.Errorf("audit chain broken at seq index %d", i)
		}
		if !bytes.Equal(prevHash, r.PrevHash) {
			return fmt.Errorf("audit prev_hash mismatch at seq index %d", i)
		}
		prevHash = r.EntryHash
	}
	return nil
}
