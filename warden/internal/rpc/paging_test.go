package rpc

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPageSizeClamp(t *testing.T) {
	for _, tc := range []struct{ in, want int32 }{{0, 50}, {-5, 50}, {101, 50}, {1, 1}, {100, 100}, {50, 50}} {
		if got := clampPageSize(tc.in); got != tc.want {
			t.Fatalf("clampPageSize(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestNameTokenRoundTrip(t *testing.T) {
	id := uuid.New()
	tok := encodeNameToken("pg-primary", id)
	k, err := decodePageToken(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if k == nil || k.Name != "pg-primary" || k.ID != id {
		t.Fatalf("round-trip mismatch: %+v", k)
	}
}

func TestTimeTokenRoundTrip(t *testing.T) {
	id := uuid.New()
	ts := time.Now().UTC().Truncate(time.Microsecond)
	k, err := decodePageToken(encodeTimeToken(ts, id))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if k == nil || !k.Time.Equal(ts) || k.ID != id {
		t.Fatalf("round-trip mismatch: %+v (ts=%s)", k, ts)
	}
}

func TestEmptyTokenIsNil(t *testing.T) {
	k, err := decodePageToken("")
	if err != nil || k != nil {
		t.Fatalf("empty token: k=%+v err=%v", k, err)
	}
}

func TestGarbageTokenErrors(t *testing.T) {
	if _, err := decodePageToken("not-base64!!"); err == nil {
		t.Fatal("expected error for garbage token")
	}
	// valid base64 wrapping invalid JSON hits the unmarshal branch
	badJSON := base64.RawURLEncoding.EncodeToString([]byte("{bad json"))
	if _, err := decodePageToken(badJSON); err == nil {
		t.Fatal("expected error for valid-b64 invalid-json token")
	}
	// valid base64+JSON but missing the mandatory tiebreak id
	noID := base64.RawURLEncoding.EncodeToString([]byte(`{"n":"foo"}`))
	if _, err := decodePageToken(noID); err == nil {
		t.Fatal("expected error for token without id")
	}
}
