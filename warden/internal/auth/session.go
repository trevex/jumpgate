package auth

import (
	"net/http"
	"strings"
)

// SessionCookie is the httpOnly cookie name carrying a browser session's opaque
// token (the same token TokenService issues for bearer use).
const SessionCookie = "jumpgate_session"

// extractToken pulls the caller's raw token from request headers. A Bearer
// Authorization header takes precedence (CLI); otherwise the jumpgate_session
// cookie is used (browser). fromCookie reports which source supplied it.
func extractToken(h http.Header) (raw string, fromCookie bool) {
	if b, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer "); ok && b != "" {
		return b, false
	}
	cookies, err := http.ParseCookie(h.Get("Cookie"))
	if err == nil {
		for _, c := range cookies {
			if c.Name == SessionCookie && c.Value != "" {
				return c.Value, true
			}
		}
	}
	return "", false
}

// ExtractToken is the exported form for callers outside this package (e.g. the
// Logout RPC re-deriving the caller's token to revoke it).
func ExtractToken(h http.Header) (raw string, fromCookie bool) { return extractToken(h) }
