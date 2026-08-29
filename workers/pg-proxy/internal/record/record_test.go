package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

type memUploader struct {
	key  string
	body []byte
	err  error
}

func (m *memUploader) Put(_ context.Context, key string, body []byte) error {
	if m.err != nil {
		return m.err
	}
	m.key, m.body = key, append([]byte(nil), body...)
	return nil
}

func TestRecorderTapAndFinish(t *testing.T) {
	up := &memUploader{}
	r := New(up, "recordings/postgres/x.ndjson", Header{V: 1, Kind: "pg", SessionID: "s1", Role: "alice", Database: "app", StartedAtMS: 1000})
	if err := r.Tap(Event{"t": 5, "type": "query", "sql": "SELECT 1"}); err != nil {
		t.Fatalf("tap: %v", err)
	}
	if err := r.Tap(Event{"t": 9, "type": "command_complete", "tag": "SELECT 1"}); err != nil {
		t.Fatalf("tap: %v", err)
	}
	rep := r.Finish(context.Background(), 2000)

	if rep.Status != "completed" {
		t.Errorf("status = %q, want completed", rep.Status)
	}
	lines := strings.Split(strings.TrimRight(string(up.body), "\n"), "\n")
	if len(lines) != 3 { // header + 2 events
		t.Fatalf("got %d NDJSON lines, want 3: %q", len(lines), up.body)
	}
	if !strings.Contains(lines[0], `"kind":"pg"`) || !strings.Contains(lines[1], `"sql":"SELECT 1"`) {
		t.Errorf("unexpected NDJSON: %q", up.body)
	}
	if rep.SizeBytes != int64(len(up.body)) {
		t.Errorf("size = %d, want %d", rep.SizeBytes, len(up.body))
	}
	sum := sha256.Sum256(up.body)
	if rep.SHA256Hex != hex.EncodeToString(sum[:]) {
		t.Errorf("sha mismatch")
	}
	if rep.StartedAtMS != 1000 || rep.EndedAtMS != 2000 {
		t.Errorf("timestamps = %d/%d", rep.StartedAtMS, rep.EndedAtMS)
	}
}

func TestRecorderCapFailClosed(t *testing.T) {
	up := &memUploader{}
	r := newWithCap(up, "k", Header{V: 1, Kind: "pg"}, 64) // tiny cap
	err := r.Tap(Event{"type": "query", "sql": strings.Repeat("x", 200)})
	if err == nil {
		t.Fatal("tap over cap: err = nil, want failure")
	}
	if rep := r.Finish(context.Background(), 1); rep.Status != "failed" {
		t.Errorf("status = %q, want failed", rep.Status)
	}
}

func TestRecorderUploadFailure(t *testing.T) {
	up := &memUploader{err: context.DeadlineExceeded}
	r := New(up, "k", Header{V: 1, Kind: "pg"})
	if rep := r.Finish(context.Background(), 1); rep.Status != "failed" {
		t.Errorf("status = %q, want failed on upload error", rep.Status)
	}
}
