package rpc_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func newServer(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	sealer := testSealer(t)
	sessionSvc, _ := testSessionService(t, pool, sealer)
	mux := http.NewServeMux()
	if err := registerServices(mux, pool, testAccessRequestService(pool), sealer, audit.New(pool), sessionSvc, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL
}

// newServerWithSession is newServer that also returns the Ed25519 public key of the
// active session signing key, for tests that verify minted admission tokens.
func newServerWithSession(t *testing.T) (*pgxpool.Pool, string, ed25519.PublicKey) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	sealer := testSealer(t)
	sessionSvc, pub := testSessionService(t, pool, sealer)
	mux := http.NewServeMux()
	if err := registerServices(mux, pool, testAccessRequestService(pool), sealer, audit.New(pool), sessionSvc, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL, pub
}

// newServerNoVault is newServer with the vault disabled (nil sealer), to exercise
// the fail-closed paths when VAULT_MASTER_KEY is unset.
func newServerNoVault(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	mux := http.NewServeMux()
	if err := registerServices(mux, pool, testAccessRequestService(pool), nil, audit.New(pool), nil, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL
}

func seedUser(t *testing.T, pool *pgxpool.Pool, email, pw string, admin bool) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	// Mirror bootstrap.EnsureAdmin: an admin also holds `**` globally via a scopeless
	// standing binding so the capability-gated management handlers admit it.
	if admin {
		role := createRoleWithCaps(t, ctx, q, "admin-"+uuid.NewString(), pgtype.UUID{}, `["**"]`)
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID:        role.ID,
			SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginAndWhoAmI(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)

	client := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	_, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "nope"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad login code = %v, want Unauthenticated", connect.CodeOf(err))
	}

	resp, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "supersecret"}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.Msg.Token == "" {
		t.Fatalf("unexpected login response: %+v", resp.Msg)
	}

	who := connect.NewRequest(&authv1.WhoAmIRequest{})
	who.Header().Set("Authorization", "Bearer "+resp.Msg.Token)
	wr, err := client.WhoAmI(ctx, who)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if wr.Msg.Email != "admin@x" {
		t.Fatalf("whoami mismatch: %+v", wr.Msg)
	}

	_, err = client.WhoAmI(ctx, connect.NewRequest(&authv1.WhoAmIRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon whoami code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

func TestLoginCookieOnly(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "cookie@x", "hunter2", false)

	client := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	resp, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
		Email:      "cookie@x",
		Password:   "hunter2",
		CookieOnly: true,
	}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Token must be absent from the body.
	if resp.Msg.Token != "" {
		t.Errorf("cookie_only=true: expected empty body token, got %q", resp.Msg.Token)
	}

	// Set-Cookie header must be present and well-formed.
	setCookie := resp.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("cookie_only=true: expected Set-Cookie header, got none")
	}
	for _, want := range []string{auth.SessionCookie + "=", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !containsStr(setCookie, want) {
			t.Errorf("Set-Cookie %q missing %q", setCookie, want)
		}
	}
}

func TestLoginBearerDefault(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "bearer@x", "hunter2", false)

	client := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	resp, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
		Email:    "bearer@x",
		Password: "hunter2",
	}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Token must be present in the body.
	if resp.Msg.Token == "" {
		t.Error("default login: expected non-empty body token")
	}

	// No Set-Cookie should be present.
	if sc := resp.Header().Get("Set-Cookie"); sc != "" {
		t.Errorf("default login: unexpected Set-Cookie header: %q", sc)
	}
}

func TestWhoAmICapabilities(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@caps", "secret1", true)
	seedUser(t, pool, "plain@caps", "secret2", false)

	client := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Helper: login and call WhoAmI, return capabilities.
	whoAmICaps := func(email, pw string) []string {
		t.Helper()
		resp, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: email, Password: pw}))
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}
		who := connect.NewRequest(&authv1.WhoAmIRequest{})
		who.Header().Set("Authorization", "Bearer "+resp.Msg.Token)
		wr, err := client.WhoAmI(ctx, who)
		if err != nil {
			t.Fatalf("whoami %s: %v", email, err)
		}
		return wr.Msg.Capabilities
	}

	// Admin holds ** globally via seedUser(admin=true).
	adminCaps := whoAmICaps("admin@caps", "secret1")
	found := false
	for _, c := range adminCaps {
		if c == "**" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("admin WhoAmI.Capabilities = %v, want it to contain \"**\"", adminCaps)
	}

	// Plain user has no global role binding — ** must not appear.
	plainCaps := whoAmICaps("plain@caps", "secret2")
	for _, c := range plainCaps {
		if c == "**" {
			t.Errorf("plain WhoAmI.Capabilities = %v, want no \"**\"", plainCaps)
		}
	}
}

// containsStr reports whether s contains substr (used to check cookie attributes).
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || containsStr(s[1:], substr)))
}

// cookieTransport is an http.RoundTripper that injects a Cookie header and
// a Sec-Fetch-Site header into every request, simulating a same-origin browser.
type cookieTransport struct {
	base       http.RoundTripper
	cookieHdr  string
	captureHdr func(http.Header) // called with the response headers (may be nil)
}

func (t *cookieTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Cookie", t.cookieHdr)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := t.base.RoundTrip(r)
	if err == nil && t.captureHdr != nil {
		t.captureHdr(resp.Header)
	}
	return resp, err
}

func TestLogoutRevokesAndClears(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "logout@x", "hunter2", false)

	ctx := context.Background()

	// Step 1: Login with CookieOnly to get a session cookie.
	loginClient := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	loginResp, err := loginClient.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
		Email:      "logout@x",
		Password:   "hunter2",
		CookieOnly: true,
	}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	setCookie := loginResp.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("expected Set-Cookie from login")
	}

	// Parse the token value out of the Set-Cookie header.
	parsed, err := http.ParseSetCookie(setCookie)
	if err != nil {
		t.Fatalf("parse Set-Cookie: %v", err)
	}
	tok := parsed.Value
	if tok == "" {
		t.Fatal("empty token in Set-Cookie")
	}
	cookieHdr := auth.SessionCookie + "=" + tok

	// Step 2: Drive Logout through the real handler+interceptor by using a
	// custom transport that injects the cookie and Sec-Fetch-Site headers so
	// the interceptor attaches the user.
	var capturedLogoutHeaders http.Header
	browserTransport := &cookieTransport{
		base:      http.DefaultTransport,
		cookieHdr: cookieHdr,
		captureHdr: func(h http.Header) {
			capturedLogoutHeaders = h.Clone()
		},
	}
	browserClient := authv1connect.NewAuthServiceClient(&http.Client{Transport: browserTransport}, url)

	_, err = browserClient.Logout(ctx, connect.NewRequest(&authv1.LogoutRequest{}))
	if err != nil {
		t.Fatalf("logout: %v", err)
	}

	// The response must clear the cookie (Max-Age=0).
	clearCookie := capturedLogoutHeaders.Get("Set-Cookie")
	if clearCookie == "" {
		t.Fatal("expected clearing Set-Cookie from Logout")
	}
	if !containsStr(clearCookie, "Max-Age=0") {
		t.Errorf("expected Max-Age=0 in clearing cookie, got: %q", clearCookie)
	}

	// Step 3: Verify the token is revoked — WhoAmI with that cookie must fail.
	whoReq := connect.NewRequest(&authv1.WhoAmIRequest{})
	whoReq.Header().Set("Cookie", cookieHdr)
	whoReq.Header().Set("Sec-Fetch-Site", "same-origin")

	whoClient := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	_, err = whoClient.WhoAmI(ctx, whoReq)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("post-logout WhoAmI code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
