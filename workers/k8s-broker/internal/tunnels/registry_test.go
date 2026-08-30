package tunnels

import (
	"testing"

	"golang.org/x/net/http2"
)

// TestRegistryChangeNotify verifies Set/Delete signal Changed() (coalesced)
// and AssetIDs() reflects the current tunnel set.
func TestRegistryChangeNotify(t *testing.T) {
	r := New()
	cc := &http2.ClientConn{}

	r.Set("asset-a", cc)
	select {
	case <-r.Changed():
	default:
		t.Fatal("Set did not signal Changed()")
	}
	if got := r.AssetIDs(); len(got) != 1 || got[0] != "asset-a" {
		t.Fatalf("AssetIDs() = %v, want [asset-a]", got)
	}

	// Multiple mutations before a reader drains coalesce into one pending signal.
	r.Set("asset-b", cc)
	r.Set("asset-c", cc)
	select {
	case <-r.Changed():
	default:
		t.Fatal("expected a pending Changed() signal")
	}
	select {
	case <-r.Changed():
		t.Fatal("Changed() should have coalesced to a single pending signal")
	default:
	}

	r.Delete("asset-a", cc)
	select {
	case <-r.Changed():
	default:
		t.Fatal("Delete did not signal Changed()")
	}
	if got := r.Get("asset-a"); got != nil {
		t.Fatalf("asset-a should be gone after Delete, got %v", got)
	}
}
