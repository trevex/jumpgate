package rpc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// capGuard performs management-plane capability checks. Embed it in each service
// that gates management RPCs. q is used for scope-derivation lookups.
type capGuard struct {
	authz authz.Authorizer
	q     *sqlc.Queries
}

// requireCap denies unless the authenticated user holds `capability` at `scope`.
func (g capGuard) requireCap(ctx context.Context, capability string, scope authz.Scope) error {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	caps, err := g.authz.CapabilitiesOnScope(ctx, u.ID, scope)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !caps.Allows(capability) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("missing capability %q", capability))
	}
	return nil
}

// requireGrantable enforces the no-escalation subset rule: every capability in
// roleCaps must be subsumed by what the actor holds at `scope`.
func (g capGuard) requireGrantable(ctx context.Context, roleCaps []string, scope authz.Scope) error {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	held, err := g.authz.CapabilitiesOnScope(ctx, u.ID, scope)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for _, c := range roleCaps {
		if !authz.Covers(held, c) {
			return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("cannot grant capability %q you do not hold at this scope", c))
		}
	}
	return nil
}

// scopeOfFolderID returns a folder scope, or Global for a NULL/zero folder id.
func scopeOfFolderID(id pgtype.UUID) authz.Scope {
	if id.Valid {
		return authz.FolderScope(uuid.UUID(id.Bytes))
	}
	return authz.GlobalScope()
}

// scopeOfRole returns the role's scope: its folder (FolderScope) or Global.
func (g capGuard) scopeOfRole(ctx context.Context, roleID uuid.UUID) (authz.Scope, error) {
	r, err := g.q.GetRole(ctx, roleID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	return scopeOfFolderID(r.FolderID), nil
}

// scopeOfGroup returns a group's governance scope: its folder (FolderScope) or Global.
func (g capGuard) scopeOfGroup(ctx context.Context, groupID uuid.UUID) (authz.Scope, error) {
	grp, err := g.q.GetGroup(ctx, groupID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return scopeOfFolderID(grp.FolderID), nil
}

// scopeOfObject derives a management scope from an object's scope columns:
// AssetScope if asset-scoped, FolderScope if folder-scoped, else Global.
func scopeOfObject(scopeFolder, scopeAsset pgtype.UUID) authz.Scope {
	if scopeAsset.Valid {
		return authz.AssetScope(uuid.UUID(scopeAsset.Bytes))
	}
	return scopeOfFolderID(scopeFolder)
}

// scopeOfBinding loads a role binding by id and returns its scope. NotFound on missing.
func (g capGuard) scopeOfBinding(ctx context.Context, bindingID uuid.UUID) (authz.Scope, error) {
	b, err := g.q.GetRoleBinding(ctx, bindingID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("role binding not found"))
	}
	return scopeOfObject(b.ScopeFolderID, b.ScopeAssetID), nil
}

// scopeOfPolicy loads a request policy by id and returns its scope. NotFound on missing.
func (g capGuard) scopeOfPolicy(ctx context.Context, policyID uuid.UUID) (authz.Scope, error) {
	p, err := g.q.GetRequestPolicy(ctx, policyID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("request policy not found"))
	}
	return scopeOfObject(p.ScopeFolderID, p.ScopeAssetID), nil
}

// roleCaps loads a role's capability patterns from role_capabilities. NotFound on missing role.
func (g capGuard) roleCaps(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	if _, err := g.q.GetRole(ctx, roleID); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	caps, err := roleCapsStrings(ctx, g.q, roleID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return caps, nil
}
