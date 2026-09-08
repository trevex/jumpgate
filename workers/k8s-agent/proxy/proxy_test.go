package proxy

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandlerForwardsWithSATokenAndImpersonation(t *testing.T) {
	// Fake API server records what it received.
	var gotAuth, gotUser, gotGroup, gotPath string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser = r.Header.Get("Impersonate-User")
		gotGroup = r.Header.Get("Impersonate-Group")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "pong")
	}))
	defer api.Close()

	// The SA token the agent injects, read fresh from disk each request.
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := New(api.URL, caFile, tokenFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive the handler directly with a request carrying impersonation headers.
	req := httptest.NewRequest(http.MethodGet, "http://tunnel/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Impersonate-User", "alice")
	req.Header.Set("Impersonate-Group", "developers")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "pong" {
		t.Fatalf("resp = %d %q", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer sa-token-123" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotUser != "alice" || gotGroup != "developers" {
		t.Fatalf("impersonation not preserved: user=%q group=%q", gotUser, gotGroup)
	}
	if gotPath != "/api/v1/namespaces/default/pods" {
		t.Fatalf("path = %q", gotPath)
	}
}

// TestIdentityPathProbesWithoutSAToken proves the reserved identity path returns
// the API server's presented chain AND never reads the SA token: the token file is
// deliberately absent, which would 500 a forward request but must not affect a probe.
func TestIdentityPathProbesWithoutSAToken(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("identity probe must not send an HTTP request to the API server")
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// SA token path that does NOT exist: a forward would fail reading it, so a
	// successful identity response proves the probe path never touches the token.
	h, err := New(api.URL, caFile, filepath.Join(dir, "does-not-exist"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://tunnel"+IdentityPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("identity resp = %d %q", rec.Code, rec.Body.String())
	}
	var got IdentityResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if len(got.ChainDER) == 0 || !bytes.Equal(got.ChainDER[0], api.Certificate().Raw) {
		t.Fatalf("identity chain does not match server certificate")
	}
}
