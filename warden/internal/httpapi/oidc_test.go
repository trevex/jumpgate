package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/oidc"
)

// stubOIDCFlow implements oidcFlow with canned results, so the login/callback
// handlers can be driven without a live IdP.
type stubOIDCFlow struct {
	authURL, sealedState string
	authErr              error

	claims      *oidc.Claims
	exchangeErr error

	userID       uuid.UUID
	provisionErr error

	syncErr error

	issuer string
}

func (s *stubOIDCFlow) AuthCodeURL() (string, string, error) {
	return s.authURL, s.sealedState, s.authErr
}

func (s *stubOIDCFlow) Exchange(context.Context, string, string, string) (*oidc.Claims, error) {
	return s.claims, s.exchangeErr
}

func (s *stubOIDCFlow) Provision(context.Context, string, string, oidc.Claims) (uuid.UUID, error) {
	return s.userID, s.provisionErr
}

func (s *stubOIDCFlow) SyncGroups(context.Context, uuid.UUID, []string) error { return s.syncErr }

func (s *stubOIDCFlow) IssuerURL() string { return s.issuer }

// stubSessionIssuer implements oidcSessionIssuer with a canned cookie.
type stubSessionIssuer struct {
	cookie *http.Cookie
	err    error
}

func (s *stubSessionIssuer) Issue(context.Context, uuid.UUID, auth.TokenMeta) (string, *http.Cookie, error) {
	return "tok", s.cookie, s.err
}

// testStateCookie builds a request-side jumpgate_oidc_state cookie, as a
// browser would carry it back on the callback request. Request cookies don't
// take Secure/HttpOnly/SameSite (those are response-only attributes).
func testStateCookie(value string) *http.Cookie {
	return &http.Cookie{Name: oidcStateCookie, Value: value} //nolint:gosec // G124: request cookie, response-only attrs don't apply.
}

func TestAuthMethodsHandler(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"disabled", false},
		{"enabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/auth/methods", nil)
			authMethodsHandler(tc.enabled)(w, r)

			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
			var body struct {
				Local bool `json:"local"`
				OIDC  bool `json:"oidc"`
			}
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !body.Local || body.OIDC != tc.enabled {
				t.Fatalf("body = %+v, want local=true oidc=%v", body, tc.enabled)
			}
		})
	}
}

// TestRouterOIDCGating verifies NewRouter only mounts /auth/oidc/* when
// RouterDeps.OIDC is set, while /auth/methods always mounts and reflects it.
func TestRouterOIDCGating(t *testing.T) {
	srv := httptest.NewServer(NewRouter(nil, RouterDeps{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/methods")
	if err != nil {
		t.Fatalf("GET /auth/methods: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Local bool `json:"local"`
		OIDC  bool `json:"oidc"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Local || body.OIDC {
		t.Fatalf("body = %+v, want local=true oidc=false", body)
	}

	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 (OIDC not configured)", path, resp.StatusCode)
		}
	}
}

func TestOIDCLoginHandler(t *testing.T) {
	svc := &stubOIDCFlow{authURL: "https://idp.example/authorize?foo=bar", sealedState: "sealed-state"}
	h := oidcLoginHandler(svc, true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != svc.authURL {
		t.Fatalf("Location = %q, want %q", loc, svc.authURL)
	}

	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == oidcStateCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatal("state cookie not set")
	}
	if found.Value != "sealed-state" {
		t.Fatalf("state cookie value = %q", found.Value)
	}
	// SameSite MUST be Lax: the callback is a top-level cross-site navigation
	// from the IdP, and a Strict cookie is withheld on exactly that request.
	if found.SameSite != http.SameSiteLaxMode {
		t.Fatalf("state cookie SameSite = %v, want Lax", found.SameSite)
	}
	if !found.HttpOnly {
		t.Fatal("state cookie should be HttpOnly")
	}
	if !found.Secure {
		t.Fatal("state cookie should be Secure when cookieSecure=true")
	}
}

func TestOIDCLoginHandlerAuthCodeURLError(t *testing.T) {
	svc := &stubOIDCFlow{authErr: errors.New("boom")}
	h := oidcLoginHandler(svc, true)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	h(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// TestOIDCCallbackHandlerMissingStateCookie covers the one callback failure
// path that needs no IdP at all: no request ever reaches the IdP without
// first hitting /auth/oidc/login, so a callback with no state cookie is
// either a forged/replayed request or a stale bookmark either way, denied.
func TestOIDCCallbackHandlerMissingStateCookie(t *testing.T) {
	h := oidcCallbackHandler(&stubOIDCFlow{}, &stubSessionIssuer{}, true, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=oidc" {
		t.Fatalf("Location = %q, want /login?error=oidc", loc)
	}
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.Contains(c, auth.SessionCookie+"=") {
			t.Fatalf("session cookie set on failed login: %q", c)
		}
	}
}

func TestOIDCCallbackHandlerExchangeFailure(t *testing.T) {
	svc := &stubOIDCFlow{exchangeErr: oidc.ErrStateMismatch}
	h := oidcCallbackHandler(svc, &stubSessionIssuer{}, true, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s&code=c", nil)
	r.AddCookie(testStateCookie("sealed"))
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=oidc" {
		t.Fatalf("Location = %q, want /login?error=oidc", loc)
	}
}

func TestOIDCCallbackHandlerSuccess(t *testing.T) {
	uid := uuid.New()
	sessionCookie := &http.Cookie{
		Name: auth.SessionCookie, Value: "session-tok", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
	svc := &stubOIDCFlow{
		claims: &oidc.Claims{Subject: "sub-1", Email: "a@example.com", EmailVerified: true},
		userID: uid,
		issuer: "https://idp.example",
	}
	iss := &stubSessionIssuer{cookie: sessionCookie}
	h := oidcCallbackHandler(svc, iss, true, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s&code=c", nil)
	r.AddCookie(testStateCookie("sealed"))
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want /", loc)
	}
	found := false
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.Contains(c, auth.SessionCookie+"=session-tok") {
			found = true
		}
	}
	if !found {
		t.Fatal("session cookie not set on success")
	}
}

func TestOIDCCallbackHandlerProvisionFailure(t *testing.T) {
	svc := &stubOIDCFlow{
		claims:       &oidc.Claims{Subject: "sub-1", EmailVerified: true},
		provisionErr: oidc.ErrDeactivated,
	}
	h := oidcCallbackHandler(svc, &stubSessionIssuer{}, true, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s&code=c", nil)
	r.AddCookie(testStateCookie("sealed"))
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login?error=oidc" {
		t.Fatalf("Location = %q, want /login?error=oidc", loc)
	}
}
