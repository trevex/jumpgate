package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
)

// CookieAuth authenticates a plain HTTP request via the same credentials the
// connect interceptor accepts: Bearer header or the jumpgate_session cookie
// (cookie requires Sec-Fetch-Site: same-origin, fail-closed CSRF). On success
// it attaches the user to the context. Requests without a valid credential
// pass through with no user attached — handlers must check UserFromContext.
func CookieAuth(
	validate func(context.Context, string) (uuid.UUID, error),
	load func(context.Context, uuid.UUID) (auth.CurrentUser, error),
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, fromCookie := auth.ExtractToken(r.Header)
			if raw != "" && (!fromCookie || r.Header.Get("Sec-Fetch-Site") == "same-origin") {
				if id, err := validate(r.Context(), raw); err == nil {
					if u, err := load(r.Context(), id); err == nil {
						r = r.WithContext(auth.WithUser(r.Context(), u))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
