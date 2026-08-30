package frontdoor_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	paseto "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/frontdoor"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

// nopUploader satisfies record.Uploader for handler tests that don't inspect the upload.
type nopUploader struct{}

func (nopUploader) Put(context.Context, string, []byte) error { return nil }

// testConn is a minimal net.Conn used only as a recorder map key.
type testConn struct{ net.Conn }

// newTestRecorder returns a working front-door recorder plus a request context
// carrying a per-connection handle (as http.Server.ConnContext would supply),
// so the fail-closed tap succeeds in direct-ServeHTTP tests.
func newTestRecorder() (*frontdoor.Recorder, context.Context) {
	rec := frontdoor.NewRecorder(nopUploader{}, "broker-0", make(chan frontdoor.SessionEnd, 8))
	ctx := rec.ConnContext(context.Background(), &testConn{})
	return rec, ctx
}

// captureRT records the request the front door forwarded to the "agent" tunnel.
type captureRT struct {
	got     *http.Request
	assetID string
}

func (c *captureRT) RoundTrip(assetID string, req *http.Request) (*http.Response, error) {
	c.assetID = assetID
	c.got = req.Clone(req.Context())
	return &http.Response{
		StatusCode: 200, Body: io.NopCloser(strings.NewReader("pong")),
		Header: make(http.Header), Proto: "HTTP/1.1",
	}, nil
}

func mint(t *testing.T, priv ed25519.PrivateKey, proto string, sub, asset uuid.UUID, groups []string) string {
	t.Helper()
	sk, _ := paseto.NewV4AsymmetricSecretKeyFromEd25519(priv)
	tok := paseto.NewToken()
	now := time.Now()
	tok.SetIssuedAt(now)
	tok.SetNotBefore(now)
	tok.SetExpiration(now.Add(time.Minute))
	tok.SetJti(uuid.New().String())
	tok.SetSubject(sub.String())
	_ = tok.Set("asset", asset.String())
	_ = tok.Set("proto", proto)
	_ = tok.Set("mode", "web")
	_ = tok.Set("cnf", "")
	_ = tok.Set("groups", groups)
	_ = tok.Set("broker_id", "broker-0")
	return tok.V4Sign(sk, nil)
}

func TestFrontDoorImpersonatesAndStrips(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sub, asset := uuid.New(), uuid.New()
	rt := &captureRT{}
	fdRec, connCtx := newTestRecorder()
	h := frontdoor.Handler(rt, sessiontoken.NewVerifier(pub), fdRec)

	tok := mint(t, priv, "kubernetes", sub, asset, []string{"developers", "system:masters"})
	req := httptest.NewRequest(http.MethodGet, "http://gw/api/v1/namespaces/default/pods", nil).WithContext(connCtx)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Impersonate-User", "root")
	req.Header.Set("Impersonate-Group", "system:masters")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if rt.got == nil {
		t.Fatal("request never forwarded")
	}
	if got := rt.got.Header.Get("Impersonate-User"); got != sub.String() {
		t.Fatalf("Impersonate-User = %q, want %q", got, sub)
	}
	gs := rt.got.Header.Values("Impersonate-Group")
	sort.Strings(gs)
	if len(gs) != 2 || gs[0] != "developers" || gs[1] != "system:masters" {
		t.Fatalf("Impersonate-Group = %v", gs)
	}
	if a := rt.got.Header.Get("Authorization"); a != "" {
		t.Fatalf("Authorization leaked to tunnel: %q", a)
	}
	if rt.got.URL.Path != "/api/v1/namespaces/default/pods" {
		t.Fatalf("path = %q", rt.got.URL.Path)
	}
	// Routing keys on the verified token's asset, never on client input.
	if rt.assetID != asset.String() {
		t.Fatalf("RoundTrip assetID = %q, want %q", rt.assetID, asset)
	}
}

func TestFrontDoorRejectsBadToken(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rt := &captureRT{}
	fdRec, _ := newTestRecorder()
	h := frontdoor.Handler(rt, sessiontoken.NewVerifier(pub), fdRec)
	req := httptest.NewRequest(http.MethodGet, "http://gw/api", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rt.got != nil {
		t.Fatal("must not forward on bad token")
	}
}

func TestFrontDoorRejectsNonKubeToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rt := &captureRT{}
	fdRec, _ := newTestRecorder()
	h := frontdoor.Handler(rt, sessiontoken.NewVerifier(pub), fdRec)
	tok := mint(t, priv, "ssh", uuid.New(), uuid.New(), nil)
	req := httptest.NewRequest(http.MethodGet, "http://gw/api", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
