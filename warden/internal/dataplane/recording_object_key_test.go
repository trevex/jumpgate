package dataplane

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRecordingObjectKey(t *testing.T) {
	id := uuid.MustParse("00000000-0000-0000-0000-0000000000ab")
	at := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	if got, want := recordingObjectKey(id, at, "ssh", "cast"),
		"recordings/ssh/2026/03/07/00000000-0000-0000-0000-0000000000ab.cast"; got != want {
		t.Errorf("ssh key = %q, want %q", got, want)
	}
	if got, want := recordingObjectKey(id, at, "postgres", "ndjson"),
		"recordings/postgres/2026/03/07/00000000-0000-0000-0000-0000000000ab.ndjson"; got != want {
		t.Errorf("postgres key = %q, want %q", got, want)
	}
}
