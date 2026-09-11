package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

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
func oidcCallbackHandler(svc oidcFlow, issuer oidcSessionIssuer, cookieSecure bool, auditLog *audit.Logger) http.HandlerFunc {
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

		claims, _, err := svc.Exchange(r.Context(), sc.Value, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		if err != nil {
			fail(exchangeFailReason(err))
			return
		}

		userID, err := svc.Provision(r.Context(), svc.IssuerURL(), claims.Subject, *claims)
		if err != nil {
			fail(provisionFailReason(err))
			return
		}

		if err := svc.SyncGroups(r.Context(), userID, claims.Groups); err != nil {
			fail("group_sync")
			return
		}

		_, cookie, err := issuer.Issue(r.Context(), userID, auth.TokenMeta{ClientIP: ip, UserAgent: r.UserAgent(), Label: "browser-sso"})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		auditOIDC(r.Context(), auditLog, oidcEventLoginSucceeded, userID, "user:"+userID.String(), "", ip)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
