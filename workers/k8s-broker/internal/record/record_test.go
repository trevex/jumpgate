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
	r := New(up, "recordings/k8s/x.ndjson", Header{V: 1, Kind: "k8s", SessionID: "s1", Role: "alice", StartedAtMS: 1000})
	if err := r.Tap(Event{"t": 5, "type": "request", "verb": "list", "resource": "pods"}); err != nil {
		t.Fatalf("tap: %v", err)
	}
	if err := r.Tap(Event{"t": 9, "type": "response", "code": 200}); err != nil {
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
	if !strings.Contains(lines[0], `"kind":"k8s"`) || !strings.Contains(lines[1], `"resource":"pods"`) {
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
	r := newWithCap(up, "k", Header{V: 1, Kind: "k8s"}, 64) // tiny cap
	err := r.Tap(Event{"type": "request", "path": strings.Repeat("x", 200)})
	if err == nil {
		t.Fatal("tap over cap: err = nil, want failure")
	}
	if rep := r.Finish(context.Background(), 1); rep.Status != "failed" {
		t.Errorf("status = %q, want failed", rep.Status)
	}
}

func TestRecorderUploadFailure(t *testing.T) {
	up := &memUploader{err: context.DeadlineExceeded}
	r := New(up, "k", Header{V: 1, Kind: "k8s"})
	if rep := r.Finish(context.Background(), 1); rep.Status != "failed" {
		t.Errorf("status = %q, want failed on upload error", rep.Status)
	}
}

func TestNewS3UploaderDisabled(t *testing.T) {
	up, err := NewS3Uploader(context.Background(), "", "", "us-east-1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if up != nil {
		t.Fatal("empty bucket must yield a nil (disabled) uploader")
	}
}
