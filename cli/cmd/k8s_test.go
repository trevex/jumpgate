package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/trevex/jumpgate/cli/internal/execcred"
	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
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

// stubK8sSessionWarden implements just CreateKubernetesSession, for the k8s
// auth cache-miss test below.
type stubK8sSessionWarden struct {
	sessionv1connect.UnimplementedSessionServiceHandler
	sessionToken    string
	gatewayEndpoint string
	expiresAt       time.Time
}

func (s *stubK8sSessionWarden) CreateKubernetesSession(_ context.Context, req *connect.Request[sessionv1.CreateKubernetesSessionRequest]) (*connect.Response[sessionv1.CreateKubernetesSessionResponse], error) {
	if req.Header().Get("Authorization") != "Bearer "+testToken {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("bad token"))
	}
	return connect.NewResponse(&sessionv1.CreateKubernetesSessionResponse{
		SessionToken:    s.sessionToken,
		GatewayEndpoint: s.gatewayEndpoint,
		ExpiresAt:       timestamppb.New(s.expiresAt),
	}), nil
}

// TestK8sAuthCacheMissMintsAndCaches exercises the cache-miss path of `k8s
// auth`: no cache entry exists, so it must mint via CreateKubernetesSession,
// persist the result to the on-disk cache, and print the minted token as an
// ExecCredential with the expiry mapped from the RPC response.
func TestK8sAuthCacheMissMintsAndCaches(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	expiry := time.Now().Add(15 * time.Minute)
	sw := &stubK8sSessionWarden{
		sessionToken:    "minted-tok",
		gatewayEndpoint: "gateway.example:443",
		expiresAt:       expiry,
	}
	mux := http.NewServeMux()
	spath, shandler := sessionv1connect.NewSessionServiceHandler(sw)
	mux.Handle(spath, shandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	flagWardenAddr = srv.URL
	flagToken = testToken
	t.Cleanup(func() { flagWardenAddr = ""; flagToken = "" })

	assetID := uuid.NewString() // a UUID short-circuits ResolveAsset with no RPC

	var out bytes.Buffer
	k8sAuthCmd.SetContext(context.Background())
	k8sAuthCmd.SetOut(&out)
	if err := runK8sAuth(k8sAuthCmd, []string{assetID}); err != nil {
		t.Fatalf("runK8sAuth: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		`"token":"minted-tok"`,
		`"kind":"ExecCredential"`,
		`"apiVersion":"client.authentication.k8s.io/v1"`,
		`"expirationTimestamp":"` + expiry.UTC().Format(time.RFC3339) + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}

	cache, err := execcred.DefaultCache()
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := cache.Load(assetID)
	if !ok {
		t.Fatal("expected cache entry after mint, found none")
	}
	if entry.Token != "minted-tok" {
		t.Errorf("cached token = %q, want minted-tok", entry.Token)
	}
	if !entry.ExpiresAt.Equal(expiry) {
		t.Errorf("cached expiry = %v, want %v", entry.ExpiresAt, expiry)
	}

	// A second call is served from cache: point the stub at nothing that could
	// answer, since a genuine cache hit never dials warden.
	flagWardenAddr = "http://unused.invalid"
	out.Reset()
	if err := runK8sAuth(k8sAuthCmd, []string{assetID}); err != nil {
		t.Fatalf("runK8sAuth (cache hit): %v", err)
	}
	if !strings.Contains(out.String(), `"token":"minted-tok"`) {
		t.Fatalf("cache-hit replay missing token: %s", out.String())
	}
}
