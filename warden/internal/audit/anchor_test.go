package audit_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/audit"
)

// fakeStore is an in-memory audit.AnchorStore for tests: it records every Put by
// key so the test can assert append-only distinct-key behavior without real S3.
type fakeStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newFakeStore() *fakeStore { return &fakeStore{objs: map[string][]byte{}} }

func (f *fakeStore) Put(_ context.Context, key string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objs[key] = append([]byte(nil), body...)
	return nil
}

// ListKeys and GetObject make fakeStore an audit.AnchorReadStore too.
func (f *fakeStore) ListKeys(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (f *fakeStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objs[key]
	if !ok {
		return nil, errors.New("not found: " + key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objs)
}

// latest returns the anchor under the lexically-greatest key (the newest tip,
// because keys are zero-padded seq).
func (f *fakeStore) latest(t *testing.T) audit.Anchor {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var maxKey string
	for k := range f.objs {
		if k > maxKey {
			maxKey = k
		}
	}
	if maxKey == "" {
		t.Fatal("no anchors written")
	}
	var a audit.Anchor
	if err := json.Unmarshal(f.objs[maxKey], &a); err != nil {
		t.Fatalf("unmarshal anchor: %v", err)
	}
	return a
}

func TestAnchorTipWritesAndSkips(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()
	store := newFakeStore()

	// Empty log: nothing to anchor.
	seq, _, err := log.AnchorTip(ctx, store, 0)
	if err != nil {
		t.Fatalf("anchor empty: %v", err)
	}
	if seq != 0 || store.count() != 0 {
		t.Fatalf("empty log should write nothing; seq=%d count=%d", seq, store.count())
	}

	for i := 0; i < 3; i++ {
		if err := log.Append(ctx, audit.Event{Type: "e", Subject: "s"}); err != nil {
			t.Fatal(err)
		}
	}

	// First anchor after appends: writes one object at the current tip.
	seq, _, err = log.AnchorTip(ctx, store, 0)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if seq == 0 {
		t.Fatal("expected a non-zero anchored tip seq")
	}
	if store.count() != 1 {
		t.Fatalf("expected 1 anchor, got %d", store.count())
	}
	a := store.latest(t)
	if a.Seq != seq {
		t.Fatalf("anchor seq %d != returned seq %d", a.Seq, seq)
	}
	if _, err := hex.DecodeString(a.EntryHash); err != nil || a.EntryHash == "" {
		t.Fatalf("anchor entry_hash not hex: %q err=%v", a.EntryHash, err)
	}

	// Tip has not advanced: no new anchor, count unchanged.
	seq2, _, err := log.AnchorTip(ctx, store, seq)
	if err != nil {
		t.Fatalf("anchor (no advance): %v", err)
	}
	if seq2 != seq {
		t.Fatalf("expected seq unchanged, got %d want %d", seq2, seq)
	}
	if store.count() != 1 {
		t.Fatalf("skip-if-not-advanced failed: count=%d", store.count())
	}

	// Advance the chain: a new distinct anchor accumulates (append-only).
	if err := log.Append(ctx, audit.Event{Type: "e", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	seq3, _, err := log.AnchorTip(ctx, store, seq)
	if err != nil {
		t.Fatalf("anchor after advance: %v", err)
	}
	if seq3 <= seq {
		t.Fatalf("expected advanced seq, got %d want > %d", seq3, seq)
	}
	if store.count() != 2 {
		t.Fatalf("expected 2 accumulated anchors, got %d", store.count())
	}
}

func TestVerifyTipAtLeastDetectsTruncation(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := log.Append(ctx, audit.Event{Type: "e", Subject: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	store := newFakeStore()
	anchoredSeq, _, err := log.AnchorTip(ctx, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := store.latest(t)
	anchorHash, err := hex.DecodeString(a.EntryHash)
	if err != nil {
		t.Fatal(err)
	}

	// Intact chain: verification against the anchor passes.
	if err := log.VerifyTipAtLeast(ctx, anchoredSeq, anchorHash); err != nil {
		t.Fatalf("intact chain should verify against anchor: %v", err)
	}

	// Truncate the tail: delete the anchored (max-seq) row. The remaining chain is
	// still internally valid (Verify passes) but VerifyTipAtLeast must catch it.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_log WHERE seq = (SELECT max(seq) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(ctx); err != nil {
		t.Fatalf("truncated chain should still pass plain Verify: %v", err)
	}
	if err := log.VerifyTipAtLeast(ctx, anchoredSeq, anchorHash); !errors.Is(err, audit.ErrTailTruncated) {
		t.Fatalf("expected ErrTailTruncated after truncation, got %v", err)
	}
}

func TestVerifyLatestAnchor(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()
	store := newFakeStore()

	// No anchor externalized yet → nothing to verify.
	if err := log.VerifyLatestAnchor(ctx, store); err != nil {
		t.Fatalf("no-anchor case should be nil, got %v", err)
	}

	for range 5 {
		if err := log.Append(ctx, audit.Event{Type: "e", Subject: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := log.AnchorTip(ctx, store, 0); err != nil {
		t.Fatal(err)
	}

	// Intact chain verifies against the latest externalized anchor.
	if err := log.VerifyLatestAnchor(ctx, store); err != nil {
		t.Fatalf("intact chain should verify against latest anchor: %v", err)
	}

	// Truncate the anchored tip: the live chain no longer covers the externalized
	// anchor, so VerifyLatestAnchor must surface ErrTailTruncated.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_log WHERE seq = (SELECT max(seq) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	if err := log.VerifyLatestAnchor(ctx, store); !errors.Is(err, audit.ErrTailTruncated) {
		t.Fatalf("after truncation: got %v, want ErrTailTruncated", err)
	}
}

// TestAnchorTipHashDetectsTruncation pins the contract RunAnchorer's in-memory verify
// relies on: the hash AnchorTip returns (captured from the trusted tip at write time)
// feeds straight into VerifyTipAtLeast — no store read — to catch later truncation.
func TestAnchorTipHashDetectsTruncation(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	ctx := context.Background()
	store := newFakeStore()

	for range 4 {
		if err := log.Append(ctx, audit.Event{Type: "e", Subject: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	seq, hash, err := log.AnchorTip(ctx, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hash == nil {
		t.Fatal("AnchorTip should return the anchored tip hash")
	}

	// Intact: the retained in-memory (seq, hash) verifies with no store access.
	if err := log.VerifyTipAtLeast(ctx, seq, hash); err != nil {
		t.Fatalf("intact chain should verify against in-memory anchor: %v", err)
	}

	// Truncate the anchored tip: the retained hash catches it.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_log WHERE seq = (SELECT max(seq) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	if err := log.VerifyTipAtLeast(ctx, seq, hash); !errors.Is(err, audit.ErrTailTruncated) {
		t.Fatalf("truncation after in-memory anchor: got %v, want ErrTailTruncated", err)
	}

	// A no-advance AnchorTip returns a nil hash (nothing re-anchored).
	if _, h, err := log.AnchorTip(ctx, store, seq); err != nil || h != nil {
		t.Fatalf("no-advance AnchorTip: h=%v err=%v, want (nil, nil)", h, err)
	}
}

func TestRunAnchorerNilStoreIsNoop(t *testing.T) {
	pool := newPool(t)
	log := audit.New(pool)
	// A nil store must return immediately (disabled), not panic or block.
	log.RunAnchorer(context.Background(), nil, 0)
}
