package mesh

import (
	"net/url"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestParseIdentity(t *testing.T) {
	id, err := ParseIdentity(mustParse(t, "spiffe://jumpgate/worker/pg-0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != (Identity{Role: "worker", ID: "pg-0"}) {
		t.Fatalf("got %+v", id)
	}

	bad := []string{
		"https://jumpgate/worker/pg-0", // wrong scheme
		"spiffe://other/worker/pg-0",   // wrong trust domain
		"spiffe://jumpgate/worker",     // 1 segment
		"spiffe://jumpgate/a/b/c",      // 3 segments
	}
	for _, raw := range bad {
		if _, err := ParseIdentity(mustParse(t, raw)); err == nil {
			t.Errorf("ParseIdentity(%q) = nil error, want error", raw)
		}
	}
}
