package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const cliCodeTTL = 60 * time.Second

// cliCodeStore maps short-lived, single-use codes to a freshly minted bearer,
// so the CLI fetches its token over its own warden connection instead of
// receiving it in the browser redirect (keeps the bearer out of browser
// history). ponytail: in-memory / per-replica — move to a shared store with
// the login throttle when warden goes multi-replica (HA milestone).
type cliCodeStore struct {
	mu  sync.Mutex
	m   map[string]cliCodeEntry
	now func() time.Time
}
type cliCodeEntry struct {
	token  string
	expiry time.Time
}

func newCLICodeStore() *cliCodeStore {
	return &cliCodeStore{m: map[string]cliCodeEntry{}, now: time.Now}
}

// put stores token under a fresh random code and returns the code. It also
// opportunistically sweeps expired entries first, so an abandoned CLI login
// (code minted, /exchange never called) doesn't leak an entry for the life of
// the process. ponytail: O(n) scan over live entries on every put — fine at
// CLI-login volumes; swap for a background ticker if this ever needs to scale
// beyond "bounded by codes minted in the last TTL".
func (s *cliCodeStore) put(token string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for c, e := range s.m {
		if now.After(e.expiry) {
			delete(s.m, c)
		}
	}
	s.m[code] = cliCodeEntry{token: token, expiry: now.Add(cliCodeTTL)}
	return code, nil
}

// take returns the token for code and deletes it (single use); ok=false if
// absent or expired.
func (s *cliCodeStore) take(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[code]
	if !ok {
		return "", false
	}
	delete(s.m, code)
	if s.now().After(e.expiry) {
		return "", false
	}
	return e.token, true
}

// isLoopbackRedirect reports whether raw is a plain-HTTP loopback URL with an
// explicit port, e.g. http://127.0.0.1:5555/cb. This is the CLI's local
// callback server; anything else (including https, bare loopback host with no
// port, or a non-loopback host) is rejected so /auth/oidc/cli/login can't be
// abused as an open redirect.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	return (host == "127.0.0.1" || host == "localhost") && u.Port() != ""
}

// oidcCLILoginHandler starts the same auth-code+PKCE flow as the browser
// login, but records the CLI's loopback redirect_uri in the sealed state so
// the callback can recognize this as a CLI flow and hand back a one-time code
// instead of a session cookie.
func oidcCLILoginHandler(svc oidcFlow, cookieSecure bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		if !isLoopbackRedirect(redirectURI) {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		authURL, sealed, err := svc.AuthCodeURLCLI(redirectURI)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		setOIDCStateCookie(w, sealed, cookieSecure)
		http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // G710: authURL is the IdP's authorize endpoint built server-side by AuthCodeURLCLI, not an echo of redirect_uri; redirect_uri itself is validated loopback-only above and only ever reaches the callback's Location query param, never a Redirect target.
	}
}

// oidcCLIExchangeHandler lets the CLI trade its one-time code (received via
// its loopback redirect) for the bearer token the callback minted. The code
// is single-use and short-lived; this is the only place the token is ever
// transmitted.
func oidcCLIExchangeHandler(store *cliCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		tok, ok := store.take(body.Code)
		if !ok {
			http.Error(w, "invalid or expired code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Token string `json:"token"`
		}{Token: tok})
	}
}
