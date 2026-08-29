// Package record captures a structured pgwire session timeline (NDJSON) and
// uploads it to object storage. It is the pg-proxy analog of ssh-proxy's asciicast
// recorder, but records statements/outcomes rather than terminal bytes.
package record

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

// maxBuffer caps the in-memory NDJSON buffer. pgwire statement logs are text and
// tiny next to a TTY cast, so buffering the whole session and doing one PutObject
// at the end is sufficient; the cap is a safety valve against a pathological run.
// ponytail: 32 MiB cap + single PutObject; move to multipart streaming only if
// real sessions ever approach this.
const maxBuffer = 32 << 20

var errFailed = errors.New("recorder buffer cap exceeded")

// Uploader writes the finished recording bytes to object storage under key.
type Uploader interface {
	Put(ctx context.Context, key string, body []byte) error
}

// Header is the first NDJSON line: session-level metadata. Asset identity is NOT
// here — it lives on the session_recordings DB row the viewer already loads.
type Header struct {
	V           int    `json:"v"`
	Kind        string `json:"kind"`
	SessionID   string `json:"session_id,omitempty"`
	Role        string `json:"role,omitempty"`
	Database    string `json:"database,omitempty"`
	StartedAtMS int64  `json:"started_at_unix_ms,omitempty"`
}

// Event is one timeline line (fields sparse per type).
type Event map[string]any

// Report is the finished-recording outcome, mapped to a RecordingInfo by the caller.
type Report struct {
	ObjectKey   string
	SizeBytes   int64
	SHA256Hex   string
	Status      string // "completed" | "failed"
	StartedAtMS int64
	EndedAtMS   int64
}

// Recorder buffers NDJSON events in memory and uploads them in one PutObject on
// Finish. Tap is safe for concurrent use by the two splice pumps.
type Recorder struct {
	up       Uploader
	key      string
	capBytes int
	startMS  int64

	mu     sync.Mutex
	buf    bytes.Buffer
	failed bool
}

// New builds a recorder and writes the header line.
func New(up Uploader, objectKey string, hdr Header) *Recorder {
	return newWithCap(up, objectKey, hdr, maxBuffer)
}

func newWithCap(up Uploader, objectKey string, hdr Header, capBytes int) *Recorder {
	r := &Recorder{up: up, key: objectKey, capBytes: capBytes, startMS: hdr.StartedAtMS}
	line, _ := json.Marshal(hdr)
	r.buf.Write(line)
	r.buf.WriteByte('\n')
	return r
}

// Tap appends one event line. It returns an error once the recorder has failed
// (cap exceeded); the audit-critical (client) pump treats that as fail-closed.
// Best-effort callers (the backend skim) ignore the returned error.
func (r *Recorder) Tap(ev Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return nil // an un-encodable event is dropped, not fatal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return errFailed
	}
	if r.buf.Len()+len(line)+1 > r.capBytes {
		r.failed = true
		return errFailed
	}
	r.buf.Write(line)
	r.buf.WriteByte('\n')
	return nil
}

// Finish uploads the buffered NDJSON and returns the report. A cap-exceeded run or
// an upload error yields status "failed".
func (r *Recorder) Finish(ctx context.Context, endMS int64) Report {
	r.mu.Lock()
	body := append([]byte(nil), r.buf.Bytes()...)
	failed := r.failed
	r.mu.Unlock()

	sum := sha256.Sum256(body)
	rep := Report{
		ObjectKey:   r.key,
		SizeBytes:   int64(len(body)),
		SHA256Hex:   hex.EncodeToString(sum[:]),
		Status:      "completed",
		StartedAtMS: r.startMS,
		EndedAtMS:   endMS,
	}
	if failed {
		rep.Status = "failed"
	}
	if err := r.up.Put(ctx, r.key, body); err != nil {
		rep.Status = "failed"
	}
	return rep
}
