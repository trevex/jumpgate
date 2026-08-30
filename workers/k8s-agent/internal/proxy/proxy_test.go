package proxy

import (
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
