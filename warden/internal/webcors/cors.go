// Package webcors provides an optional, allowlist-gated CORS middleware for
// browser dev against warden's user API. Empty allowlist = pass-through no-op
// (production serves the SPA same-origin and needs no CORS).
package webcors

import (
	"net/http"
	"slices"
)

// New returns a middleware that adds CORS headers for requests whose Origin is
// in the allowed list. When allowed is empty, the middleware is a no-op and the
// inner handler is called directly (no preflight handling, no CORS headers).
func New(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && slices.Contains(allowed, origin) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Add("Vary", "Origin")
				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms")
					h.Set("Access-Control-Max-Age", "600")
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
