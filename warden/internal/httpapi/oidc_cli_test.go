package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/oidc"
)

func TestIsLoopbackRedirect(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"http://127.0.0.1:5555/cb", true},
		{"http://localhost:5555/cb", true},
		{"https://evil.com/cb", false},
		{"http://127.0.0.1/cb", false}, // no port
		{"http://evil.com:80/cb", false},
		{"://not a url", false},
	} {
		if got := isLoopbackRedirect(tc.raw); got != tc.want {
			t.Errorf("isLoopbackRedirect(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestCLICodeStore(t *testing.T) {
	s := newCLICodeStore()
	code, err := s.put("tok-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	tok, ok := s.take(code)
	if !ok || tok != "tok-1" {
		t.Fatalf("take = (%q, %v), want (tok-1, true)", tok, ok)
	}

	// Single-use: a second take must miss.
	if _, ok := s.take(code); ok {
		t.Fatal("second take succeeded, want single-use")
	}
}

func TestCLICodeStoreExpiry(t *testing.T) {
	s := newCLICodeStore()
	now := time.Now()
	s.now = func() time.Time { return now }

	code, err := s.put("tok-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	s.now = func() time.Time { return now.Add(cliCodeTTL + time.Second) }
	if _, ok := s.take(code); ok {
		t.Fatal("take succeeded on expired code")
	}
}

func TestOIDCCLIExchangeHandler(t *testing.T) {
	store := newCLICodeStore()
	code, err := store.put("tok-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	h := oidcCLIExchangeHandler(store)

	t.Run("valid code", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"code": code})
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/oidc/cli/exchange", bytes.NewReader(body))
		h(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", cc)
		}
		var resp struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Token != "tok-1" {
			t.Fatalf("token = %q, want tok-1", resp.Token)
		}
	})

	t.Run("bogus code", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"code": "bogus"})
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/oidc/cli/exchange", bytes.NewReader(body))
		h(w, r)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("non-POST", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/oidc/cli/exchange", nil)
		h(w, r)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", w.Code)
		}
	})
}

func TestOIDCCLILoginHandler(t *testing.T) {
	t.Run("non-loopback redirect_uri rejected", func(t *testing.T) {
		svc := &stubOIDCFlow{authURL: "https://idp.example/authorize", sealedState: "sealed"}
		h := oidcCLILoginHandler(svc, true)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/oidc/cli/login?redirect_uri=https://evil.com/cb", nil)
		h(w, r)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("valid loopback redirect_uri", func(t *testing.T) {
		svc := &stubOIDCFlow{authURL: "https://idp.example/authorize?foo=bar", sealedState: "sealed-state"}
		h := oidcCLILoginHandler(svc, true)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/oidc/cli/login?redirect_uri=http://127.0.0.1:5555/cb", nil)
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
	})
}

func TestOIDCCallbackHandlerCLISuccess(t *testing.T) {
	uid := uuid.New()
	const cliRedirect = "http://127.0.0.1:5555/cb"
	svc := &stubOIDCFlow{
		claims:      &oidc.Claims{Subject: "sub-1", EmailVerified: true},
		cliRedirect: cliRedirect,
		userID:      uid,
	}
	store := newCLICodeStore()
	h := oidcCallbackHandler(svc, &stubSessionIssuer{}, true, nil, store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s&code=c", nil)
	r.AddCookie(testStateCookie("sealed"))
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cliRedirect+"?code=") {
		t.Fatalf("Location = %q, want prefix %q", loc, cliRedirect+"?code=")
	}
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.Contains(c, auth.SessionCookie+"=") {
			t.Fatalf("session cookie set on CLI login: %q", c)
		}
	}

	code := strings.TrimPrefix(loc, cliRedirect+"?code=")
	tok, ok := store.take(code)
	if !ok {
		t.Fatal("code did not resolve in store")
	}
	if tok != "tok" { // stubSessionIssuer.Issue always returns "tok"
		t.Fatalf("token = %q, want tok", tok)
	}
}

func TestOIDCCallbackHandlerCLIProvisionFailure(t *testing.T) {
	const cliRedirect = "http://127.0.0.1:5555/cb"
	svc := &stubOIDCFlow{
		claims:       &oidc.Claims{Subject: "sub-1", EmailVerified: true},
		cliRedirect:  cliRedirect,
		provisionErr: oidc.ErrDeactivated,
	}
	h := oidcCallbackHandler(svc, &stubSessionIssuer{}, true, nil, newCLICodeStore())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=s&code=c", nil)
	r.AddCookie(testStateCookie("sealed"))
	h(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cliRedirect+"?error=") {
		t.Fatalf("Location = %q, want prefix %q", loc, cliRedirect+"?error=")
	}
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.Contains(c, auth.SessionCookie+"=") {
			t.Fatalf("session cookie set on failed CLI login: %q", c)
		}
	}
}
