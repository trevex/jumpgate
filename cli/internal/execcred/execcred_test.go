package execcred

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCacheRoundTripAndExpiry(t *testing.T) {
	dir := t.TempDir()
	c := &Cache{Dir: dir, Margin: time.Minute}
	if _, ok := c.Load("asset-1"); ok {
		t.Fatal("expected miss on empty cache")
	}
	if err := c.Store("asset-1", "tok", time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, ok := c.Load("asset-1")
	if !ok || got.Token != "tok" {
		t.Fatalf("expected hit, got %+v ok=%v", got, ok)
	}
	// A token expiring within the margin is a miss.
	if err := c.Store("asset-2", "tok2", time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Load("asset-2"); ok {
		t.Fatal("token within margin must be a miss")
	}
}

func TestExecCredentialJSON(t *testing.T) {
	exp := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	b, err := MarshalExecCredential("tok", exp)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"apiVersion":"client.authentication.k8s.io/v1"`,
		`"kind":"ExecCredential"`,
		`"token":"tok"`,
		`"expirationTimestamp":"2026-08-30T12:00:00Z"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
}

func TestStoreIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	c := &Cache{Dir: dir, Margin: time.Minute}
	if err := c.Store("a", "t", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// no leftover temp files
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file leaked: %s", e.Name())
		}
	}
}
