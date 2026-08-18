// Package audit implements a hash-chained, tamper-evident audit log.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

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

// Append writes one entry, chaining from the current tail (serialized via a
// row lock in a transaction so concurrent appends can't fork the chain).
func (l *Logger) Append(ctx context.Context, e Event) error {
	if e.Details == nil {
		e.Details = []byte("{}")
	}
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)

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
	return tx.Commit(ctx)
}

// Verify recomputes the whole chain and returns an error at the first mismatch.
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
