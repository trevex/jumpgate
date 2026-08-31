package access

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// CreateRole creates a custom role and its capabilities in one transaction: the role
// row plus one role_capability per requested pattern, committed together so a
// capability-insert failure leaves no role row. The caller's capability is gated by
// the handler at the role's (request) folder scope. Returns the created role with its
// capabilities and folder path.
func (s *Service) CreateRole(ctx context.Context, name string, folderID pgtype.UUID, caps []string) (RoleResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RoleResult{}, connect.NewError(connect.CodeInternal, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)
	r, err := qtx.CreateRole(ctx, sqlc.CreateRoleParams{Name: name, FolderID: folderID})
	if err != nil {
		return RoleResult{}, apierr.MapWrite(err)
	}
	for _, cap := range caps {
		sc, ac, qu := authz.NormalizeCap(cap)
		if err := qtx.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{RoleID: r.ID, Scope: sc, Action: ac, Qualifier: qu}); err != nil {
			return RoleResult{}, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RoleResult{}, connect.NewError(connect.CodeInternal, err)
	}
	return s.roleResult(ctx, r)
}

// ResolveRole resolves uuid | name (global) | <role>.<folder-path> (scoped) to a
// role. The read gate (access:role:read) is applied at the resolved role's folder
// scope after the lookup. A missing role is NotFound.
func (s *Service) ResolveRole(ctx context.Context, caller uuid.UUID, ref string) (RoleResult, error) {
	var role sqlc.Role
	if id, perr := uuid.Parse(ref); perr == nil {
		r, err := s.q.GetRole(ctx, id)
		if err != nil {
			return RoleResult{}, apierr.RoleNotFoundOrInternal(err)
		}
		role = r
	} else if name, folderPath, ok := strings.Cut(ref, "."); ok {
		folderID, err := resolveFolderIDByPath(ctx, s.q, folderPath)
		if err != nil {
			return RoleResult{}, apierr.RoleNotFoundOrInternal(err)
		}
		r, err := s.q.GetRoleByFolderAndName(ctx, sqlc.GetRoleByFolderAndNameParams{FolderID: pgconv.UUID(folderID), Name: name})
		if err != nil {
			return RoleResult{}, apierr.RoleNotFoundOrInternal(err)
		}
		role = r
	} else {
		r, err := s.q.GetRoleByNameGlobal(ctx, ref)
		if err != nil {
			return RoleResult{}, apierr.RoleNotFoundOrInternal(err)
		}
		role = r
	}
	if err := s.guard.RequireReadCap(ctx, caller, authz.RoleReadCap, apiguard.ScopeOfFolderID(role.FolderID)); err != nil {
		return RoleResult{}, err
	}
	return s.roleResult(ctx, role)
}

// ListRoles browses roles under a parent (default root), returning only the roles the
// caller may see — those they hold, may request, or may manage via access:role:read.
// Not cap-gated: an unrelated caller sees an empty page, not an error. Cascade
// descends the whole subtree; otherwise only roles homed directly in the parent
// folder (or, for root, the global/folder-less roles). Returns the page rows and an
// opaque next-page token.
func (s *Service) ListRoles(ctx context.Context, caller uuid.UUID, parentRef string, cascade bool, pageSize int32, pageToken string) ([]RoleResult, string, error) {
	parent, err := resolveParentFolderRef(ctx, s.q, parentRef)
	if err != nil {
		return nil, "", err
	}
	ids, err := s.authz.VisibleRolesUnder(ctx, caller, parent, cascade)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	if len(ids) == 0 {
		return nil, "", nil
	}
	limit := apipage.ClampPageSize(pageSize)
	key, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListRolesByIDsPagedParams{Column1: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgconv.Text(key.Name)
		params.AfterID = pgconv.UUID(key.ID)
	}
	rows, err := s.q.ListRolesByIDsPaged(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	pathByFolder := map[uuid.UUID]string{}
	out := make([]RoleResult, 0, len(rows))
	for i := range rows {
		caps, err := apiguard.RoleCapsStrings(ctx, s.q, rows[i].ID)
		if err != nil {
			return nil, "", connect.NewError(connect.CodeInternal, err)
		}
		res := RoleResult{Role: rows[i], Caps: caps}
		if rows[i].FolderID.Valid {
			fid := apiguard.UUIDFromPg(rows[i].FolderID)
			p, ok := pathByFolder[fid]
			if !ok {
				p, err = s.q.FolderPath(ctx, fid)
				if err != nil {
					return nil, "", connect.NewError(connect.CodeInternal, err)
				}
				pathByFolder[fid] = p
			}
			res.FolderPath = p
		}
		out = append(out, res)
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the standard
	// strict-last-page tradeoff). The sort key is name.
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeNameToken(last.Name, last.ID)
	}
	return out, next, nil
}

// GetRole fetches a single role by id. A missing role is NotFound; the read gate
// (access:role:read) is applied at the role's folder scope.
func (s *Service) GetRole(ctx context.Context, caller, id uuid.UUID) (RoleResult, error) {
	r, err := s.q.GetRole(ctx, id)
	if err != nil {
		return RoleResult{}, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	if err := s.guard.RequireReadCap(ctx, caller, authz.RoleReadCap, apiguard.ScopeOfFolderID(r.FolderID)); err != nil {
		return RoleResult{}, err
	}
	return s.roleResult(ctx, r)
}

// DeleteRole removes a role and everything that references it, transactionally, so
// that "the role is gone" implies no one holds it and any live sessions it granted
// end. The caller's capability (access:role:delete at the role's folder scope) is
// gated by the handler. The cascade (bindings, role-grant edges in both directions,
// request policies for which the role is the requestable role, and the active grants
// it conferred — revoked so their live sessions are torn down) runs in the deleter;
// policies that reference the role only as a requester/approver survive with that
// column cleared.
func (s *Service) DeleteRole(ctx context.Context, actor, roleID uuid.UUID) error {
	if err := s.deleter.DeleteRoleCascade(ctx, actor, roleID); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// GetRoleDisplay returns a role's decision context — the role plus the capabilities
// it grants (what an approval confers) — for rendering an approval/request row.
// Authorized by access:role:read at the role's folder scope OR the caller being party
// to a pending access request that references the role (requester or standing
// approver). A missing role is NotFound; an existing-but-unauthorized role is
// PermissionDenied (roles are non-topology, so this matches GetRole).
func (s *Service) GetRoleDisplay(ctx context.Context, caller, id uuid.UUID) (RoleResult, error) {
	r, err := s.q.GetRole(ctx, id)
	if err != nil {
		return RoleResult{}, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	// Authorize: access:role:read at the role's folder scope OR party to a pending
	// access request referencing this role. On cap-deny, preserve the original
	// PermissionDenied unless the request-party path grants the read.
	if capErr := s.guard.RequireReadCap(ctx, caller, authz.RoleReadCap, apiguard.ScopeOfFolderID(r.FolderID)); capErr != nil {
		if s.reqReads == nil {
			return RoleResult{}, capErr
		}
		allowed, aerr := s.reqReads.CanReadForRequest(ctx, caller, accessrequest.ReqEntityRole, id)
		if aerr != nil {
			return RoleResult{}, connect.NewError(connect.CodeInternal, aerr)
		}
		if !allowed {
			return RoleResult{}, capErr
		}
	}
	return s.roleResult(ctx, r)
}

// GetRoleAccess returns the caller's management capabilities on one role.
// PermissionDenied (not NotFound) when the caller has no relationship to the role,
// because roles are not catalog topology. A missing role is NotFound.
func (s *Service) GetRoleAccess(ctx context.Context, caller, id uuid.UUID) ([]string, error) {
	role, err := s.q.GetRole(ctx, id)
	if err != nil {
		return nil, apierr.RoleNotFoundOrInternal(err)
	}
	caps, err := s.authz.CapabilitiesOnScope(ctx, caller, apiguard.ScopeOfFolderID(role.FolderID))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no access to role"))
	}
	return []string(caps), nil
}

// ExplainRole enumerates every derivation by which a user holds a role on an asset.
// It delegates to the RoleResolver; the admin/self authorization is applied by the
// handler. Unknown-but-parseable ids yield holds=false, paths=[] (reported as "no
// access", not an error): this is intentional for the admin/self introspection tool.
func (s *Service) ExplainRole(ctx context.Context, userID, roleID, assetID uuid.UUID) (bool, []authz.ExplainPath, error) {
	return s.roles.ExplainRole(ctx, userID, roleID, assetID)
}
