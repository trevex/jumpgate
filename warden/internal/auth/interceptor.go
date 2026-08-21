package auth

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

// CurrentUser is the authenticated principal attached to a request context.
type CurrentUser struct {
	ID    uuid.UUID
	Email string
}

type userCtxKey struct{}

// WithUser returns a context carrying u.
func WithUser(ctx context.Context, u CurrentUser) context.Context {
	return context.WithValue(ctx, userCtxKey{}, u)
}

// UserFromContext returns the current user, if authenticated.
func UserFromContext(ctx context.Context) (CurrentUser, bool) {
	u, ok := ctx.Value(userCtxKey{}).(CurrentUser)
	return u, ok
}

// userLookup resolves a validated token to a CurrentUser.
type userLookup interface {
	Validate(ctx context.Context, rawToken string) (uuid.UUID, error)
	Load(ctx context.Context, id uuid.UUID) (CurrentUser, error)
}

// NewInterceptor authenticates requests via two credential sources:
//
//   - Bearer token (`Authorization: Bearer <token>`): used by CLI clients.
//     A valid token always attaches the user.
//
//   - Session cookie (`jumpgate_session=<token>`): used by browser clients.
//     A valid token attaches the user only when the request also carries
//     `Sec-Fetch-Site: same-origin`, which browsers set automatically and
//     cross-origin attackers cannot forge. Without that header the cookie is
//     ignored (fail-closed CSRF defence).
//
// The interceptor NEVER rejects; it only attaches a user when a valid,
// CSRF-safe credential is present. Per-RPC guards (capability checks /
// UserFromContext) enforce auth requirements, which keeps Login callable
// anonymously.
func NewInterceptor(lookup userLookup) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Spec().IsClient {
				return next(ctx, req)
			}
			raw, fromCookie := extractToken(req.Header())
			if raw != "" && (!fromCookie || req.Header().Get("Sec-Fetch-Site") == "same-origin") {
				if id, err := lookup.Validate(ctx, raw); err == nil {
					if u, err := lookup.Load(ctx, id); err == nil {
						ctx = WithUser(ctx, u)
					}
				}
			}
			return next(ctx, req)
		}
	}
}
