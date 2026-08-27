// Package apiguard provides the shared management-plane capability gate and scope
// derivations used by the ConnectRPC handlers. It is a transport leaf: it imports
// only authz, sqlc, connect, and the pgx/uuid types — never a domain module — so
// the wiring package can import the domain handlers (which depend on this) without
// forming an import cycle.
//
// Guard methods take the authenticated caller's id explicitly rather than reading
// it from the request context. The context principal accessor lives in the auth
// package (a domain module); keeping it out of this leaf is what preserves the
// no-domain-import rule. Handlers extract the caller (auth.UserFromContext) and
// pass its id in.
package apiguard

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Guard performs management-plane capability checks. Q is used for scope-derivation
// lookups.
type Guard struct {
	Authz *authz.Authorizer
	Q     *sqlc.Queries
}

// New constructs a Guard.
func New(a *authz.Authorizer, q *sqlc.Queries) Guard {
	return Guard{Authz: a, Q: q}
}

// RequireCap denies unless caller holds `capability` at `scope`.
func (g Guard) RequireCap(ctx context.Context, caller uuid.UUID, capability string, scope authz.Scope) error {
	caps, err := g.Authz.CapabilitiesOnScope(ctx, caller, scope)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !caps.Allows(capability) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("missing capability %q", capability))
	}
	return nil
}

// RequireReadCap is the READ-gate variant of RequireCap: it denies unless caller
// holds `objectReadCap` OR the subtree-wide catalog:folder:read (authz.FolderReadCap)
// at `scope`. It is the single-sourced gate for per-object read RPCs (Get/Resolve/
// *Access of asset/role/group), so a delegate holding catalog:folder:read on an
// ancestor folder can OPEN the objects it now sees. READ-only: it must NOT be used
// for authoring/connect gates, and it does not touch grantable/subset logic.
func (g Guard) RequireReadCap(ctx context.Context, caller uuid.UUID, objectReadCap string, scope authz.Scope) error {
	caps, err := g.Authz.CapabilitiesOnScope(ctx, caller, scope)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !caps.ReadAllowed(objectReadCap) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("missing capability %q", objectReadCap))
	}
	return nil
}

// RequireGrantable enforces the no-escalation subset rule: every capability in
// roleCaps must be subsumed by what caller holds at `scope`.
func (g Guard) RequireGrantable(ctx context.Context, caller uuid.UUID, roleCaps []string, scope authz.Scope) error {
	held, err := g.Authz.CapabilitiesOnScope(ctx, caller, scope)
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

// ScopeOfFolderID returns a folder scope, or Global for a NULL/zero folder id.
func ScopeOfFolderID(id pgtype.UUID) authz.Scope {
	if id.Valid {
		return authz.FolderScope(uuid.UUID(id.Bytes))
	}
	return authz.GlobalScope()
}

// ScopeOfObject derives a management scope from an object's scope columns:
// AssetScope if asset-scoped, FolderScope if folder-scoped, else Global.
func ScopeOfObject(scopeFolder, scopeAsset pgtype.UUID) authz.Scope {
	if scopeAsset.Valid {
		return authz.AssetScope(uuid.UUID(scopeAsset.Bytes))
	}
	return ScopeOfFolderID(scopeFolder)
}

// ScopeOfRole returns the role's scope: its folder (FolderScope) or Global.
func (g Guard) ScopeOfRole(ctx context.Context, roleID uuid.UUID) (authz.Scope, error) {
	r, err := g.Q.GetRole(ctx, roleID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	return ScopeOfFolderID(r.FolderID), nil
}

// ScopeOfGroup returns a group's governance scope: its folder (FolderScope) or Global.
func (g Guard) ScopeOfGroup(ctx context.Context, groupID uuid.UUID) (authz.Scope, error) {
	grp, err := g.Q.GetGroup(ctx, groupID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return ScopeOfFolderID(grp.FolderID), nil
}

// ScopeOfBinding loads a role binding by id and returns its scope. NotFound on missing.
func (g Guard) ScopeOfBinding(ctx context.Context, bindingID uuid.UUID) (authz.Scope, error) {
	b, err := g.Q.GetRoleBinding(ctx, bindingID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("role binding not found"))
	}
	return ScopeOfObject(b.ScopeFolderID, b.ScopeAssetID), nil
}

// ScopeOfPolicy loads a request policy by id and returns its scope. NotFound on missing.
func (g Guard) ScopeOfPolicy(ctx context.Context, policyID uuid.UUID) (authz.Scope, error) {
	p, err := g.Q.GetRequestPolicy(ctx, policyID)
	if err != nil {
		return authz.Scope{}, connect.NewError(connect.CodeNotFound, errors.New("request policy not found"))
	}
	return ScopeOfObject(p.ScopeFolderID, p.ScopeAssetID), nil
}

// RoleCaps loads a role's capability patterns from role_capabilities. NotFound on missing role.
func (g Guard) RoleCaps(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	if _, err := g.Q.GetRole(ctx, roleID); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	caps, err := RoleCapsStrings(ctx, g.Q, roleID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return caps, nil
}

// RoleCapsStrings queries role_capabilities for the given role and returns the
// reconstructed capability pattern strings. Used wherever a role's capability list
// is needed for display or no-escalation checks.
func RoleCapsStrings(ctx context.Context, q *sqlc.Queries, roleID uuid.UUID) ([]string, error) {
	rows, err := q.RoleCapabilityRows(ctx, roleID)
	if err != nil {
		return nil, err
	}
	caps := make([]string, 0, len(rows))
	for _, row := range rows {
		caps = append(caps, authz.ReconstructCap(row.Scope, row.Action, row.Qualifier))
	}
	return caps, nil
}

// UUIDFromPg converts a pgtype.UUID to a uuid.UUID.
//
// Precondition: the caller must ensure the value is meaningful for its use —
// either the column is NOT NULL, or the caller has already checked u.Valid.
// A NULL (u.Valid == false) yields uuid.Nil rather than an error, so passing an
// unguarded nullable value silently substitutes the zero UUID. Callers reading
// nullable columns (e.g. roles/groups folder_id) MUST guard on u.Valid first.
// The one deliberate consumer of the NULL→uuid.Nil mapping is the recording
// asset filter, which treats uuid.Nil as "no filter" (fleet-wide).
func UUIDFromPg(u pgtype.UUID) uuid.UUID { return u.Bytes }
