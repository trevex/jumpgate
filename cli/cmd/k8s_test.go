package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/cli/internal/execcred"
)

// TestK8sAuthCacheHitPrintsExecCredentialNoRPC exercises the cache-hit path of
// `k8s auth`: a pre-seeded, still-valid cache entry must be printed as an
// ExecCredential without ever reaching warden (the asset ref is a UUID, so
// ResolveAsset short-circuits, and CreateKubernetesSession is never called —
// flagWardenAddr points nowhere real, so a network call would fail the test).
func TestK8sAuthCacheHitPrintsExecCredentialNoRPC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	flagWardenAddr = "http://unused.invalid"
	flagToken = "tok-abc"
	t.Cleanup(func() { flagWardenAddr = ""; flagToken = "" })

	assetID := uuid.NewString()
	cache, err := execcred.DefaultCache()
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	if err := cache.Store(assetID, "cached-tok", expiry); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	k8sAuthCmd.SetContext(context.Background())
	k8sAuthCmd.SetOut(&out)
	if err := runK8sAuth(k8sAuthCmd, []string{assetID}); err != nil {
		t.Fatalf("runK8sAuth: %v", err)
	}
	got := out.String()
	for _, want := range []string{`"token":"cached-tok"`, `"kind":"ExecCredential"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
}
