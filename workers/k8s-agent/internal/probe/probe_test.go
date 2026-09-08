package probe_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trevex/jumpgate/workers/k8s-agent/internal/probe"
)

// TestProbeCapturesPresentedChain proves the probe returns exactly the certificate
// the API server presents, over a plain TLS handshake, without needing (or reading)
// any ServiceAccount token — Probe has no token input by construction.
func TestProbeCapturesPresentedChain(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("probe must stop at the TLS handshake and never send an HTTP request")
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()

	ev, err := probe.Probe(context.Background(), api.URL)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(ev.ChainDER) == 0 {
		t.Fatal("no chain captured")
	}
	if !bytes.Equal(ev.ChainDER[0], api.Certificate().Raw) {
		t.Fatalf("captured leaf != server certificate")
	}
	if ev.ServerName != "127.0.0.1" {
		t.Fatalf("server name = %q, want 127.0.0.1", ev.ServerName)
	}
}

// TestProbeFailsClosedOnUnreachable proves a probe against a dead endpoint errors
// rather than returning empty evidence.
func TestProbeFailsClosedOnUnreachable(t *testing.T) {
	if _, err := probe.Probe(context.Background(), "https://127.0.0.1:1"); err == nil {
		t.Fatal("expected error probing an unreachable API server")
	}
}
