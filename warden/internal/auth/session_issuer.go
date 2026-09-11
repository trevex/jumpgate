package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SessionIssuer mints the opaque jumpgate_session and builds its cookie. It is
// the shared login tail for every auth source (local password and OIDC), so a
// browser session established by any source is byte-identical.
type SessionIssuer struct {
	tokens       *TokenService
	cookieSecure bool
	sessionTTL   time.Duration
}

// NewSessionIssuer constructs a SessionIssuer.
func NewSessionIssuer(tokens *TokenService, cookieSecure bool, sessionTTL time.Duration) *SessionIssuer {
	return &SessionIssuer{tokens: tokens, cookieSecure: cookieSecure, sessionTTL: sessionTTL}
}

// Issue creates a session token for userID and returns it plus the matching
// cookie. Callers put the token in a response body (CLI) or set the cookie
// (browser via http.SetCookie / Set-Cookie header).
func (si *SessionIssuer) Issue(ctx context.Context, userID uuid.UUID, meta TokenMeta) (string, *http.Cookie, error) {
	tok, err := si.tokens.Issue(ctx, userID, si.sessionTTL, meta)
	if err != nil {
		return "", nil, err
	}
	c := &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Strict set; Secure is config-gated.
		Name: SessionCookie, Value: tok, Path: "/",
		MaxAge: int(si.sessionTTL / time.Second), HttpOnly: true, Secure: si.cookieSecure, SameSite: http.SameSiteStrictMode,
	}
	return tok, c, nil
}
