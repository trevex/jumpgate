package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AnchorStore is the object-store capability the anchorer/verifier needs. It is
// defined here (consumer-side) so the audit package stays decoupled from any
// concrete S3 client: the wiring adapts warden's real object-store client to it.
// Put MUST use a distinct key per anchor (never overwrite) so anchors accumulate
// append-only. ListKeys/GetObject are used ONCE at startup to recover the last
// anchor of a previous run (see RunAnchorer); steady-state verification reads no
// object store at all. recording.S3Presigner satisfies all three.
type AnchorStore interface {
	Put(ctx context.Context, key string, body []byte) error
	ListKeys(ctx context.Context, prefix string) ([]string, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
}

// Anchor is the small JSON object written to the object store to pin the audit
// hash-chain tip at a point in time. Its purpose is to make TAIL TRUNCATION
// detectable: the in-DB chain remains internally valid if an attacker deletes
// the most-recent rows, but a previously-externalized anchor at seq A with hash
// H proves those rows once existed. VerifyTipAtLeast cross-checks the live chain
// against an anchor.
type Anchor struct {
	Seq        int64  `json:"seq"`
	EntryHash  string `json:"entry_hash"` // hex-encoded
	AnchoredAt string `json:"anchored_at"`
}

// anchorKeyPrefix is the object-store key namespace for anchors. Anchors are
// written under distinct, zero-padded-seq keys so they accumulate append-only —
// combined with object-store immutability/versioning this is the tamper-evidence.
const anchorKeyPrefix = "audit-anchors/"

// anchorKey returns the append-only object key for a given tip seq. The seq is
// zero-padded to sort lexicographically, so listing the prefix yields anchors in
// chain order and the lexically-greatest key is the latest anchor.
func anchorKey(seq int64) string {
	return fmt.Sprintf("%s%020d.json", anchorKeyPrefix, seq)
}

// AnchorTip reads the current chain tip and, if it has advanced past lastSeq,
// writes a fresh anchor object to the store and returns the new tip's (seq, hash).
// If the tip has not advanced (or the log is empty) it returns (lastSeq, nil) and
// writes nothing — a nil hash signals "no new anchor". The returned hash is the one
// just externalized, captured here from a freshly-read (trusted) tip, so the caller
// can retain it as an in-memory reference for later truncation checks without
// re-reading the DB (which would be circular). All object-store and DB errors are
// returned to the caller, which logs them (fail-open) — anchoring never blocks.
func (l *Logger) AnchorTip(ctx context.Context, store AnchorStore, lastSeq int64) (int64, []byte, error) {
	tip, err := sqlc.New(l.pool).AuditChainTip(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		// Empty log: nothing to anchor yet.
		return lastSeq, nil, nil
	}
	if err != nil {
		return lastSeq, nil, fmt.Errorf("read chain tip: %w", err)
	}
	seq := tip.Seq
	if seq <= lastSeq {
		// Tip has not advanced since the last anchor: no new anchor needed.
		return lastSeq, nil, nil
	}

	body, err := json.Marshal(Anchor{
		Seq:        seq,
		EntryHash:  hex.EncodeToString(tip.EntryHash),
		AnchoredAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return lastSeq, nil, fmt.Errorf("marshal anchor: %w", err)
	}
	if err := store.Put(ctx, anchorKey(seq), body); err != nil {
		return lastSeq, nil, fmt.Errorf("put anchor: %w", err)
	}
	return seq, tip.EntryHash, nil
}

// RunAnchorer periodically anchors the audit hash-chain tip to the object store AND
// verifies the live chain still covers the last anchor. Every interval it (1) checks
// the chain against the last anchor it knows, then (2) writes a new anchor if the tip
// advanced. It is best-effort defense-in-depth: ErrTailTruncated is logged at ERROR
// (the in-DB chain no longer covers a provably-externalized tip — investigate now);
// operational errors are WARN and retried next tick; nothing ever blocks. Exits on
// ctx.Done(). Start only when an object store is configured (nil → immediate return).
//
// COST: the last anchor's (seq, hash) is tracked IN MEMORY — captured from AnchorTip
// at write time, when the DB read is trusted — so steady-state verification is just
// two indexed DB lookups (VerifyTipAtLeast) with NO object-store access. The store is
// LISTed exactly once, at startup, to recover the previous run's last anchor; that is
// the only way to detect truncation that happened while warden was down (the reference
// of truth must live outside the DB being verified). See VerifyLatestAnchor.
func (l *Logger) RunAnchorer(ctx context.Context, store AnchorStore, interval time.Duration) {
	if store == nil {
		slog.Info("audit anchorer disabled: no object store configured")
		return
	}

	// lastSeq/lastHash: the highest tip we have anchored (and its hash). Skips
	// re-writing when the chain has not advanced, and is the reference the periodic
	// verify checks against without touching the store.
	var lastSeq int64
	var lastHash []byte

	// Bootstrap (one-time, the ONLY store read on the verify path): recover the last
	// anchor from a previous run so a restart still detects truncation that happened
	// while warden was down. A missing/unreadable anchor just means "nothing to verify
	// yet" — the first tick below will write one.
	if a, err := l.latestAnchor(ctx, store); err != nil {
		slog.Warn("audit anchor bootstrap read failed", "err", err)
	} else if a != nil {
		if h, derr := hex.DecodeString(a.EntryHash); derr == nil {
			lastSeq, lastHash = a.Seq, h
		}
	}

	verify := func() {
		if lastHash == nil {
			return // nothing anchored yet
		}
		switch err := l.VerifyTipAtLeast(ctx, lastSeq, lastHash); {
		case errors.Is(err, ErrTailTruncated):
			slog.Error("AUDIT CHAIN TAMPER DETECTED: live chain no longer covers the last externalized anchor", "anchored_seq", lastSeq)
		case err != nil && ctx.Err() == nil:
			slog.Warn("audit integrity verify failed", "err", err)
		}
	}

	verify() // startup check against the recovered anchor

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			verify() // in-memory reference — 2 indexed DB reads, no store access
			seq, hash, err := l.AnchorTip(ctx, store, lastSeq)
			if err != nil {
				slog.Warn("audit anchor failed", "err", err)
				continue
			}
			if hash != nil { // tip advanced → a new anchor was written
				slog.Info("audit chain tip anchored", "seq", seq)
				lastSeq, lastHash = seq, hash
			}
		}
	}
}

// latestAnchor returns the most recently externalized anchor (the lexically-greatest
// key under the anchor prefix), or nil if none exist. It LISTs the whole prefix, so
// it is used sparingly: once at RunAnchorer startup, and by the on-demand
// VerifyLatestAnchor. Steady-state anchoring/verification does not call it.
func (l *Logger) latestAnchor(ctx context.Context, store AnchorStore) (*Anchor, error) {
	keys, err := store.ListKeys(ctx, anchorKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("list anchors: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	// Keys are zero-padded seq (see anchorKey), so the lexically greatest is the latest.
	latest := keys[0]
	for _, k := range keys[1:] {
		if k > latest {
			latest = k
		}
	}
	rc, err := store.GetObject(ctx, latest)
	if err != nil {
		return nil, fmt.Errorf("get anchor %s: %w", latest, err)
	}
	defer func() { _ = rc.Close() }()
	var a Anchor
	if err := json.NewDecoder(rc).Decode(&a); err != nil {
		return nil, fmt.Errorf("decode anchor %s: %w", latest, err)
	}
	return &a, nil
}

// VerifyLatestAnchor reads the most recent externalized anchor and cross-checks the
// live audit chain against it via VerifyTipAtLeast. nil means the chain still covers
// the anchored tip (or nothing has been anchored yet); ErrTailTruncated means the
// chain was truncated/rewritten below a tip that was provably externalized — tamper
// evidence the in-DB Verify alone cannot detect. Other errors are operational
// (store unreachable, malformed anchor). This is the on-demand entry point (a future
// admin verify RPC/CLI); the background path in RunAnchorer avoids the LIST.
func (l *Logger) VerifyLatestAnchor(ctx context.Context, store AnchorStore) error {
	a, err := l.latestAnchor(ctx, store)
	if err != nil {
		return err
	}
	if a == nil {
		return nil // nothing externalized yet
	}
	hash, err := hex.DecodeString(a.EntryHash)
	if err != nil {
		return fmt.Errorf("anchor at seq %d has a malformed entry_hash: %w", a.Seq, err)
	}
	return l.VerifyTipAtLeast(ctx, a.Seq, hash)
}

// ErrTailTruncated indicates the live audit chain no longer covers an anchored
// tip: either the live chain is shorter than the anchor's seq, or the row at the
// anchored seq has a different entry_hash. Both mean the most-recent entries were
// deleted or rewritten after they were externally anchored — tamper evidence that
// the in-DB-only Verify cannot detect.
var ErrTailTruncated = errors.New("audit chain truncated or rewritten below anchored tip")

// VerifyTipAtLeast cross-checks the live chain against a known anchor (seq, hash,
// as recorded in an Anchor object). It confirms the chain still has a row at
// seq >= anchorSeq AND that the row at seq == anchorSeq has entry_hash == anchorHash.
// A missing row at anchorSeq, a live tip below anchorSeq, or a hash mismatch all
// return ErrTailTruncated. This is the in-DB half of anchor verification: an
// operator or admin tool feeds it the last anchor read back from the object store.
// It is additive — the existing Verify (whole-chain integrity) is unchanged.
func (l *Logger) VerifyTipAtLeast(ctx context.Context, anchorSeq int64, anchorHash []byte) error {
	q := sqlc.New(l.pool)
	tip, err := q.AuditChainTip(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		// Live log is empty but an anchor exists → everything after genesis was
		// truncated.
		return ErrTailTruncated
	}
	if err != nil {
		return fmt.Errorf("read chain tip: %w", err)
	}
	if tip.Seq < anchorSeq {
		return ErrTailTruncated
	}
	got, err := q.AuditEntryHashAtSeq(ctx, anchorSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTailTruncated
	}
	if err != nil {
		return fmt.Errorf("read entry at seq %d: %w", anchorSeq, err)
	}
	if !bytes.Equal(got, anchorHash) {
		return ErrTailTruncated
	}
	return nil
}
