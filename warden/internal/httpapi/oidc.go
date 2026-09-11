package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/oidc"
)

// OIDC login audit event types.
const (
	oidcEventLoginSucceeded = "auth.oidc.login.succeeded"
	oidcEventLoginFailed    = "auth.oidc.login.failed"
)

// oidcStateCookie carries the sealed state/nonce/PKCE-verifier bundle across
// the redirect round trip to the IdP and back. Scoped to /auth/oidc so it is
// never sent on unrelated requests.
const oidcStateCookie = "jumpgate_oidc_state"

// oidcFlow is the subset of *oidc.Service the browser OIDC routes drive.
// Defined consumer-side so a test can inject canned claims/errors without a
// live IdP or network discovery; *oidc.Service satisfies it structurally.
type oidcFlow interface {
	AuthCodeURL() (authURL, sealedState string, err error)
	AuthCodeURLCLI(cliRedirect string) (authURL, sealedState string, err error)
	Exchange(ctx context.Context, sealedState, gotState, code string) (*oidc.Claims, string, error)
	Provision(ctx context.Context, issuer, subject string, c oidc.Claims) (uuid.UUID, error)
	SyncGroups(ctx context.Context, userID uuid.UUID, groups []string) error
	IssuerURL() string
}

// oidcSessionIssuer is the subset of *auth.SessionIssuer the callback handler
// drives, defined consumer-side for the same testability reason.
type oidcSessionIssuer interface {
	Issue(ctx context.Context, userID uuid.UUID, meta auth.TokenMeta) (string, *http.Cookie, error)
}

var (
	_ oidcFlow          = (*oidc.Service)(nil)
	_ oidcSessionIssuer = (*auth.SessionIssuer)(nil)
)

// auditOIDC appends an OIDC login audit event best-effort. A nil logger (no
// Audit dep wired) silently disables OIDC audit events without affecting the
// login flow itself.
func auditOIDC(ctx context.Context, log *audit.Logger, eventType string, actorID uuid.UUID, subject, reason, ip string) {
	if log == nil {
		return
	}
	kv := map[string]string{"ip": ip}
	if reason != "" {
		kv["reason"] = reason
	}
	details, _ := json.Marshal(kv) // map[string]string always marshals
	if err := log.Append(ctx, audit.Event{Type: eventType, ActorID: actorID, Subject: subject, Details: details}); err != nil {
		slog.Error("audit append failed", "event", eventType, "err", err)
	}
}

// authMethodsHandler reports which login methods the client may offer. Always
// mounted, authenticated or not, so the login page can decide what to render.
func authMethodsHandler(oidcEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Local bool `json:"local"`
			OIDC  bool `json:"oidc"`
		}{Local: true, OIDC: oidcEnabled})
	}
}

// oidcLoginHandler starts the auth-code+PKCE flow: mints state/nonce/PKCE,
// stashes them in a short-lived cookie, and redirects to the IdP.
func oidcLoginHandler(svc oidcFlow, cookieSecure bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authURL, sealed, err := svc.AuthCodeURL()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// SameSite=Lax is required, not Strict: the callback arrives as a
		// top-level cross-site navigation (the IdP redirecting the browser back
		// to us), and a Strict cookie is withheld on exactly that request — the
		// callback would never see the state cookie it needs to validate.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Lax set; Secure is config-gated.
			Name: oidcStateCookie, Value: sealed, Path: "/auth/oidc",
			MaxAge: 300, HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// exchangeFailReason maps a Service.Exchange error to an audit reason code.
func exchangeFailReason(err error) string {
	switch {
	case errors.Is(err, oidc.ErrStateMismatch):
		return "state_mismatch"
	case errors.Is(err, oidc.ErrNonceMismatch):
		return "nonce_mismatch"
	case errors.Is(err, oidc.ErrNoIDToken):
		return "no_id_token"
	case errors.Is(err, oidc.ErrUnverifiedEmail):
		return "unverified_email"
	default:
		return "exchange"
	}
}

// provisionFailReason maps a Service.Provision error to an audit reason code.
func provisionFailReason(err error) string {
	switch {
	case errors.Is(err, oidc.ErrEmailCollision):
		return "email_collision"
	case errors.Is(err, oidc.ErrDeactivated):
		return "deactivated"
	default:
		return "internal"
	}
}

// oidcCallbackHandler completes the flow: verifies state+nonce, exchanges the
// code, JIT-provisions/resolves the local user, reconciles IdP groups, and
// issues the same jumpgate_session cookie a local-password login would. Any
// failure clears the state cookie, audits the reason, and redirects to the
// login page rather than leaking detail to the browser.
//
// When the sealed state carries a CLI loopback redirect (set by
// oidcCLILoginHandler), this is a CLI flow instead: on success the bearer is
// handed to the CLI via a one-time code through store rather than a session
// cookie (the bearer never touches the browser), and failures redirect to the
// CLI's loopback server with an error query param instead of /login.
func oidcCallbackHandler(svc oidcFlow, issuer oidcSessionIssuer, cookieSecure bool, auditLog *audit.Logger, store *cliCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := auth.PeerHost(r.RemoteAddr)
		fail := func(reason string) {
			auditOIDC(r.Context(), auditLog, oidcEventLoginFailed, uuid.Nil, "", reason, ip)
			http.Redirect(w, r, "/login?error=oidc", http.StatusFound)
		}

		sc, cookieErr := r.Cookie(oidcStateCookie)
		// Clear the state cookie regardless of outcome: it is single-use.
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Lax set; Secure is config-gated.
			Name: oidcStateCookie, Value: "", Path: "/auth/oidc", MaxAge: -1,
			HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode,
		})
		if cookieErr != nil {
			fail("missing_state_cookie")
			return
		}

		// cli-ness is only known post-Exchange (it's carried inside the sealed
		// state). A CLI request whose Exchange fails falls back to fail(), same
		// as the browser: the state cookie round trip is browser-side either
		// way, and the CLI's loopback server will simply time out waiting for a
		// code — acceptable for a rare failure mode.
		claims, cliRedirect, err := svc.Exchange(r.Context(), sc.Value, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		if err != nil {
			fail(exchangeFailReason(err))
			return
		}

		failFlow := func(reason string) {
			if cliRedirect == "" {
				fail(reason)
				return
			}
			auditOIDC(r.Context(), auditLog, oidcEventLoginFailed, uuid.Nil, "", reason, ip)
			http.Redirect(w, r, cliRedirect+"?error="+url.QueryEscape(reason), http.StatusFound)
		}

		userID, err := svc.Provision(r.Context(), svc.IssuerURL(), claims.Subject, *claims)
		if err != nil {
			failFlow(provisionFailReason(err))
			return
		}

		if err := svc.SyncGroups(r.Context(), userID, claims.Groups); err != nil {
			failFlow("group_sync")
			return
		}

		label := "browser-sso"
		if cliRedirect != "" {
			label = "cli-sso"
		}
		token, cookie, err := issuer.Issue(r.Context(), userID, auth.TokenMeta{ClientIP: ip, UserAgent: r.UserAgent(), Label: label})
		if err != nil {
			if cliRedirect != "" {
				failFlow("internal")
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if cliRedirect == "" {
			http.SetCookie(w, cookie)
			auditOIDC(r.Context(), auditLog, oidcEventLoginSucceeded, userID, "user:"+userID.String(), "", ip)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// CLI flow: the bearer never reaches the browser. Stash it behind a
		// short-lived, single-use code and hand only the code to the CLI's
		// loopback server via the redirect query string.
		code, err := store.put(token)
		if err != nil {
			failFlow("internal")
			return
		}
		auditOIDC(r.Context(), auditLog, oidcEventLoginSucceeded, userID, "user:"+userID.String(), "", ip)
		http.Redirect(w, r, cliRedirect+"?code="+url.QueryEscape(code), http.StatusFound)
	}
}
