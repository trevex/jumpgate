package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// capGuard adapts the leaf apiguard.Guard to the still-in-rpc handlers: it reads
// the authenticated caller from the request context (auth.UserFromContext) and
// delegates the capability decision to the guard. The apiguard package is a
// transport leaf and must not import auth, so this context read stays here; the
// gate logic itself lives in apiguard. Embed capGuard in each server that gates
// management RPCs.
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

// requireGrantable enforces the no-escalation subset rule: every capability in
// roleCaps must be subsumed by what the actor holds at `scope`.
func (g capGuard) requireGrantable(ctx context.Context, roleCaps []string, scope authz.Scope) error {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return g.guard.RequireGrantable(ctx, u.ID, roleCaps, scope)
}

// scopeOfRole returns the role's scope: its folder (FolderScope) or Global.
func (g capGuard) scopeOfRole(ctx context.Context, roleID uuid.UUID) (authz.Scope, error) {
	return g.guard.ScopeOfRole(ctx, roleID)
}

// scopeOfGroup returns a group's governance scope: its folder (FolderScope) or Global.
func (g capGuard) scopeOfGroup(ctx context.Context, groupID uuid.UUID) (authz.Scope, error) {
	return g.guard.ScopeOfGroup(ctx, groupID)
}

// scopeOfBinding loads a role binding by id and returns its scope. NotFound on missing.
func (g capGuard) scopeOfBinding(ctx context.Context, bindingID uuid.UUID) (authz.Scope, error) {
	return g.guard.ScopeOfBinding(ctx, bindingID)
}

// scopeOfPolicy loads a request policy by id and returns its scope. NotFound on missing.
func (g capGuard) scopeOfPolicy(ctx context.Context, policyID uuid.UUID) (authz.Scope, error) {
	return g.guard.ScopeOfPolicy(ctx, policyID)
}

// roleCaps loads a role's capability patterns from role_capabilities. NotFound on missing role.
func (g capGuard) roleCaps(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	return g.guard.RoleCaps(ctx, roleID)
}
