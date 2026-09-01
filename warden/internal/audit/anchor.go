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

// AnchorStore is the minimal object-store write capability the anchorer needs.
// It is defined here (consumer-side) so the audit package stays decoupled from
// any concrete S3 client: the wiring adapts warden's real object-store client to
// this interface. Put MUST use a distinct key per anchor (never overwrite) so
// anchors accumulate append-only.
type AnchorStore interface {
	Put(ctx context.Context, key string, body []byte) error
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
// writes a fresh anchor object to the store and returns the new tip seq. If the
// tip has not advanced (or the log is empty) it returns lastSeq unchanged and
// writes nothing. All object-store and DB errors are returned to the caller,
// which logs them (fail-open) — anchoring never blocks audit writes.
func (l *Logger) AnchorTip(ctx context.Context, store AnchorStore, lastSeq int64) (int64, error) {
	tip, err := sqlc.New(l.pool).AuditChainTip(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		// Empty log: nothing to anchor yet.
		return lastSeq, nil
	}
	if err != nil {
		return lastSeq, fmt.Errorf("read chain tip: %w", err)
	}
	seq := tip.Seq
	if seq <= lastSeq {
		// Tip has not advanced since the last anchor: no new anchor needed.
		return lastSeq, nil
	}

	body, err := json.Marshal(Anchor{
		Seq:        seq,
		EntryHash:  hex.EncodeToString(tip.EntryHash),
		AnchoredAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return lastSeq, fmt.Errorf("marshal anchor: %w", err)
	}
	if err := store.Put(ctx, anchorKey(seq), body); err != nil {
		return lastSeq, fmt.Errorf("put anchor: %w", err)
	}
	return seq, nil
}

// RunAnchorer periodically anchors the audit hash-chain tip to the object store.
// Every interval it reads the tip and, if it advanced since the last anchor,
// writes a distinct append-only anchor object. It is best-effort defense-in-depth:
// any error (store unreachable, DB error) is LOGGED and never blocks anything, and
// the loop retries on the next tick. It exits on ctx.Done() (graceful shutdown).
// The caller MUST only start it when an object store is configured; a nil store is
// treated as "not configured" and the goroutine returns immediately with a notice.
func (l *Logger) RunAnchorer(ctx context.Context, store AnchorStore, interval time.Duration) {
	if store == nil {
		slog.Info("audit anchorer disabled: no object store configured")
		return
	}
	// lastSeq tracks the highest tip we have already anchored, so we skip writing
	// when the chain has not advanced (avoids churn / duplicate anchors).
	var lastSeq int64
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newSeq, err := l.AnchorTip(ctx, store, lastSeq)
			if err != nil {
				// Fail-open: log and keep going. A future tick retries.
				slog.Warn("audit anchor failed", "err", err)
				continue
			}
			if newSeq != lastSeq {
				slog.Info("audit chain tip anchored", "seq", newSeq)
				lastSeq = newSeq
			}
		}
	}
}

// AnchorReadStore reads back externalized anchors so the live chain can be verified
// against them. It is the read counterpart of AnchorStore; recording.S3Presigner
// satisfies it (ListKeys + GetObject).
type AnchorReadStore interface {
	ListKeys(ctx context.Context, prefix string) ([]string, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
}

// VerifyLatestAnchor reads the most recent externalized anchor and cross-checks the
// live audit chain against it via VerifyTipAtLeast. nil means the chain still covers
// the anchored tip (or nothing has been anchored yet); ErrTailTruncated means the
// chain was truncated/rewritten below a tip that was provably externalized — tamper
// evidence the in-DB Verify alone cannot detect. Other errors are operational
// (store unreachable, malformed anchor).
func (l *Logger) VerifyLatestAnchor(ctx context.Context, store AnchorReadStore) error {
	keys, err := store.ListKeys(ctx, anchorKeyPrefix)
	if err != nil {
		return fmt.Errorf("list anchors: %w", err)
	}
	if len(keys) == 0 {
		return nil // nothing externalized yet
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
		return fmt.Errorf("get anchor %s: %w", latest, err)
	}
	defer func() { _ = rc.Close() }()
	var a Anchor
	if err := json.NewDecoder(rc).Decode(&a); err != nil {
		return fmt.Errorf("decode anchor %s: %w", latest, err)
	}
	hash, err := hex.DecodeString(a.EntryHash)
	if err != nil {
		return fmt.Errorf("anchor %s has a malformed entry_hash: %w", latest, err)
	}
	return l.VerifyTipAtLeast(ctx, a.Seq, hash)
}

// RunIntegrityVerifier cross-checks the live audit chain against the latest
// externalized anchor once at startup (catching truncation that happened while
// warden was down) and then every interval. It is the read side of the tamper-
// evidence the anchorer writes: ErrTailTruncated is logged at ERROR (the in-DB chain
// no longer covers a provably-externalized tip — investigate now); operational errors
// are WARN. Best-effort — never blocks. Exits on ctx.Done(). Start only when an
// object store is configured (a nil store returns immediately).
func (l *Logger) RunIntegrityVerifier(ctx context.Context, store AnchorReadStore, interval time.Duration) {
	if store == nil {
		return
	}
	check := func() {
		switch err := l.VerifyLatestAnchor(ctx, store); {
		case errors.Is(err, ErrTailTruncated):
			slog.Error("AUDIT CHAIN TAMPER DETECTED: live chain no longer covers the last externalized anchor", "err", err)
		case err != nil && ctx.Err() == nil:
			slog.Warn("audit integrity verify failed", "err", err)
		}
	}
	check()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
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
