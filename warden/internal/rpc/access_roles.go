package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// CreateRole creates a custom role (admin only).
func (s *AccessServer) CreateRole(ctx context.Context, req *connect.Request[accessv1.CreateRoleRequest]) (*connect.Response[accessv1.CreateRoleResponse], error) {
	folderID, _, err := optUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	if err := s.requireCap(ctx, "access:role:create", scopeOfFolderID(folderID)); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)
	r, err := qtx.CreateRole(ctx, gen.CreateRoleParams{Name: req.Msg.Name, FolderID: folderID})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	for _, cap := range req.Msg.Capabilities {
		sc, ac, qu := authz.NormalizeCap(cap)
		if err := qtx.InsertRoleCapability(ctx, gen.InsertRoleCapabilityParams{RoleID: r.ID, Scope: sc, Action: ac, Qualifier: qu}); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	m, err := s.roleMsgWithPath(ctx, r)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CreateRoleResponse{Role: m}), nil
}

// ResolveRole resolves uuid | name (global) | <role>.<folder-path> (scoped) to a role id (admin only).
func (s *AccessServer) ResolveRole(ctx context.Context, req *connect.Request[accessv1.ResolveRoleRequest]) (*connect.Response[accessv1.ResolveRoleResponse], error) {
	ref := req.Msg.Ref
	var role gen.Role
	if id, perr := uuid.Parse(ref); perr == nil {
		r, err := s.q.GetRole(ctx, id)
		if err != nil {
			return nil, roleNotFoundOrInternal(err)
		}
		role = r
	} else if name, folderPath, ok := strings.Cut(ref, "."); ok {
		folderID, err := resolveFolderIDByPath(ctx, s.q, folderPath)
		if err != nil {
			return nil, roleNotFoundOrInternal(err)
		}
		r, err := s.q.GetRoleByFolderAndName(ctx, gen.GetRoleByFolderAndNameParams{FolderID: pgUUID(folderID), Name: name})
		if err != nil {
			return nil, roleNotFoundOrInternal(err)
		}
		role = r
	} else {
		r, err := s.q.GetRoleByNameGlobal(ctx, ref)
		if err != nil {
			return nil, roleNotFoundOrInternal(err)
		}
		role = r
	}
	if err := s.requireCap(ctx, "access:role:read", scopeOfFolderID(role.FolderID)); err != nil {
		return nil, err
	}
	m, err := s.roleMsgWithPath(ctx, role)
	if err != nil {
		return nil, err
	}
	path := m.Name
	if m.FolderPath != "" {
		path = m.Name + "." + m.FolderPath
	}
	return connect.NewResponse(&accessv1.ResolveRoleResponse{RoleId: role.ID.String(), Path: path}), nil
}

// ListRoles browses roles under a parent (default root), returning only the
// roles the caller may see — those they hold, may request, or may manage via
// access:role:read. Not cap-gated: an unrelated caller sees an empty page, not
// an error. Cascade descends the whole subtree; otherwise only roles homed
// directly in the parent folder (or, for root, the global/folder-less roles).
func (s *AccessServer) ListRoles(ctx context.Context, req *connect.Request[accessv1.ListRolesRequest]) (*connect.Response[accessv1.ListRolesResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	parent, err := resolveParentFolderRef(ctx, s.q, req.Msg.Parent)
	if err != nil {
		return nil, err
	}
	ids, err := s.authz.VisibleRolesUnder(ctx, u.ID, parent, req.Msg.Cascade)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRolesResponse{}
	if len(ids) == 0 {
		return connect.NewResponse(out), nil
	}
	limit := clampPageSize(req.Msg.PageSize)
	key, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListRolesByIDsPagedParams{Column1: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgText(key.Name)
		params.AfterID = pgUUID(key.ID)
	}
	rows, err := s.q.ListRolesByIDsPaged(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	pathByFolder := map[uuid.UUID]string{}
	for i := range rows {
		caps, err := roleCapsStrings(ctx, s.q, rows[i].ID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		m := toAccessRoleMsg(rows[i], caps)
		if rows[i].FolderID.Valid {
			fid := uuidFromPg(rows[i].FolderID)
			p, ok := pathByFolder[fid]
			if !ok {
				p, err = s.q.FolderPath(ctx, fid)
				if err != nil {
					return nil, connect.NewError(connect.CodeInternal, err)
				}
				pathByFolder[fid] = p
			}
			m.FolderPath = p
		}
		out.Roles = append(out.Roles, m)
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeNameToken takes the SORT-KEY
	// column: here name.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Name, last.ID)
	}
	return connect.NewResponse(out), nil
}

// GetRole fetches a single role by id (admin only).
func (s *AccessServer) GetRole(ctx context.Context, req *connect.Request[accessv1.GetRoleRequest]) (*connect.Response[accessv1.GetRoleResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	r, err := s.q.GetRole(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	if err := s.requireCap(ctx, "access:role:read", scopeOfFolderID(r.FolderID)); err != nil {
		return nil, err
	}
	m, err := s.roleMsgWithPath(ctx, r)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetRoleResponse{Role: m}), nil
}

// DeleteRole removes a role and everything that references it, transactionally, so
// that "the role is gone" implies no one holds it and any live sessions it granted
// end. Gated on access:role:delete at the role's folder scope. The cascade (bindings,
// role-grant edges in both directions, request policies for which the role is the
// requestable role, and the active grants it conferred — revoked so their live
// sessions are torn down) runs in the deleter; policies that reference the role only
// as a requester/approver survive with that column cleared. A missing role is
// NotFound.
func (s *AccessServer) DeleteRole(ctx context.Context, req *connect.Request[accessv1.DeleteRoleRequest]) (*connect.Response[accessv1.DeleteRoleResponse], error) {
	id, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	// scopeOfRole loads the role, returning NotFound if it is absent (roles are
	// non-topology, but a delete of a missing role is a plain NotFound).
	scope, err := s.scopeOfRole(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:role:delete", scope); err != nil {
		return nil, err
	}
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if err := s.deleter.DeleteRoleCascade(ctx, caller.ID, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRoleResponse{}), nil
}

// GetRoleDisplay returns a role's decision context — id, name, folder path, and the
// capabilities it grants (the capabilities are what an approval confers, so they are
// included) — for rendering an approval/request row. Authorized by access:role:read
// at the role's folder scope OR the caller being party to a pending access request
// that references the role (requester or standing approver). Denial codes match
// GetRole: a missing role is NotFound; an existing-but-unauthorized role is
// PermissionDenied (roles are non-topology).
func (s *AccessServer) GetRoleDisplay(ctx context.Context, req *connect.Request[accessv1.GetRoleDisplayRequest]) (*connect.Response[accessv1.GetRoleDisplayResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	r, err := s.q.GetRole(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	// Authorize: access:role:read at the role's folder scope OR party to a pending
	// access request referencing this role. On cap-deny, preserve the original
	// PermissionDenied unless the request-party path grants the read.
	if capErr := s.requireCap(ctx, "access:role:read", scopeOfFolderID(r.FolderID)); capErr != nil {
		caller, ok := auth.UserFromContext(ctx)
		if !ok || s.reqReads == nil {
			return nil, capErr
		}
		allowed, aerr := s.reqReads.CanReadForRequest(ctx, caller.ID, accessrequest.ReqEntityRole, id)
		if aerr != nil {
			return nil, connect.NewError(connect.CodeInternal, aerr)
		}
		if !allowed {
			return nil, capErr
		}
	}
	m, err := s.roleMsgWithPath(ctx, r)
	if err != nil {
		return nil, err
	}
	caps, err := s.roleCaps(ctx, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetRoleDisplayResponse{Role: &accessv1.RoleDisplay{
		Id:           r.ID.String(),
		Name:         r.Name,
		FolderPath:   m.FolderPath,
		Capabilities: caps,
	}}), nil
}

// GetRoleAccess returns the caller's management capabilities on one role.
// PermissionDenied (not NotFound) when the caller has no relationship to the
// role, because roles are not catalog topology.
func (s *AccessServer) GetRoleAccess(ctx context.Context, req *connect.Request[accessv1.GetRoleAccessRequest]) (*connect.Response[accessv1.GetRoleAccessResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	role, err := s.q.GetRole(ctx, id)
	if err != nil {
		return nil, roleNotFoundOrInternal(err)
	}
	caps, err := s.authz.CapabilitiesOnScope(ctx, u.ID, scopeOfFolderID(role.FolderID))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no access to role"))
	}
	return connect.NewResponse(&accessv1.GetRoleAccessResponse{Capabilities: []string(caps)}), nil
}

// ExplainRole enumerates every derivation by which a user holds a role on an
// asset. Admins may explain anyone; a non-admin may only explain themselves.
//
// user_id is parsed to a canonical uuid before the self-check, so a non-admin
// may pass their own id in any parseable form (e.g. uppercase or URN).
// Unknown-but-parseable user_id/role_id/asset_id yield holds=false, paths=[]
// (reported as "no access", not an error): this is intentional for the
// admin/self introspection tool.
func (s *AccessServer) ExplainRole(ctx context.Context, req *connect.Request[accessv1.ExplainRoleRequest]) (*connect.Response[accessv1.ExplainRoleResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	userID, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	// Callers may always explain their own access; explaining another user's
	// access requires the management read cap (admins hold ** globally).
	if userID != caller.ID {
		if err := s.requireCap(ctx, "access:role:read", authz.GlobalScope()); err != nil {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("may only explain your own access"))
		}
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	holds, paths, err := s.roles.ExplainRole(ctx, userID, roleID, assetID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ExplainRoleResponse{Holds: holds}
	for _, p := range paths {
		mp := &accessv1.ExplainRolePath{BindingId: p.BindingID.String(), Subject: p.Subject}
		for _, st := range p.Steps {
			mp.Steps = append(mp.Steps, &accessv1.RoleGrantPathStep{
				RoleId:     st.RoleID.String(),
				ObjectKind: st.ObjectKind,
				ObjectId:   st.ObjectID.String(),
				Via:        st.Via,
			})
		}
		out.Paths = append(out.Paths, mp)
	}
	return connect.NewResponse(out), nil
}
