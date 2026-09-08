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

	r.Set("asset-a", cc, []byte("cert-a"))
	select {
	case <-r.Changed():
	default:
		t.Fatal("Set did not signal Changed()")
	}
	if got := r.AssetIDs(); len(got) != 1 || got[0] != "asset-a" {
		t.Fatalf("AssetIDs() = %v, want [asset-a]", got)
	}

	// Multiple mutations before a reader drains coalesce into one pending signal.
	r.Set("asset-b", cc, []byte("cert-b"))
	r.Set("asset-c", cc, []byte("cert-c"))
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

// TestRegistryBindingsCarryPerAssetCert proves each binding carries exactly the
// cert captured for its asset — the material warden re-derives the asset id from,
// so an agent for one asset can never be advertised under another asset's cert.
func TestRegistryBindingsCarryPerAssetCert(t *testing.T) {
	r := New()
	ccA, ccB := &http2.ClientConn{}, &http2.ClientConn{}
	r.Set("asset-a", ccA, []byte("cert-a"))
	r.Set("asset-b", ccB, []byte("cert-b"))

	got := map[string]string{}
	for _, b := range r.Bindings() {
		got[b.AssetID] = string(b.CertDER)
	}
	if got["asset-a"] != "cert-a" || got["asset-b"] != "cert-b" {
		t.Fatalf("bindings = %v, want asset-a=cert-a asset-b=cert-b", got)
	}
}
