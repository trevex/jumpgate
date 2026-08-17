package auth

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

// CurrentUser is the authenticated principal attached to a request context.
type CurrentUser struct {
	ID      uuid.UUID
	Email   string
	IsAdmin bool
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

// RequireAdmin returns a Connect error unless the context user is an admin.
func RequireAdmin(ctx context.Context) error {
	u, ok := UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if !u.IsAdmin {
		return connect.NewError(connect.CodePermissionDenied, errors.New("admin required"))
	}
	return nil
}

// userLookup resolves a validated token to a CurrentUser.
type userLookup interface {
	Validate(ctx context.Context, rawToken string) (uuid.UUID, error)
	Load(ctx context.Context, id uuid.UUID) (CurrentUser, error)
}

// NewInterceptor authenticates requests via `Authorization: Bearer <token>`.
// It NEVER rejects; it only attaches a user when a valid token is present.
// Per-RPC guards (RequireAdmin / UserFromContext) enforce auth requirements,
// which keeps Login callable anonymously.
func NewInterceptor(lookup userLookup) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Spec().IsClient {
				return next(ctx, req)
			}
			raw, ok := strings.CutPrefix(req.Header().Get("Authorization"), "Bearer ")
			if ok && raw != "" {
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
