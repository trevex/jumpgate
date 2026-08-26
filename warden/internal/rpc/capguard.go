package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// capGuard adapts the leaf apiguard.Guard to the still-in-rpc handlers: it reads the
// authenticated caller from the request context (auth.UserFromContext) and delegates
// the capability decision to the guard. The apiguard package is a transport leaf and
// must not import auth, so this context read stays here; the gate logic itself lives
// in apiguard. Embed capGuard in each server that gates management RPCs.
type capGuard struct {
	guard apiguard.Guard
}

// requireCap denies unless the authenticated user holds `capability` at `scope`.
func (g capGuard) requireCap(ctx context.Context, capability string, scope authz.Scope) error {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return g.guard.RequireCap(ctx, u.ID, capability, scope)
}
