package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// AccessServer implements accessv1connect.AccessServiceHandler: all authorization
// configuration (roles, grants, standing bindings, request policies) plus the
// admin-or-self ExplainRole introspection.
type AccessServer struct {
	q        *gen.Queries
	roles    *authz.RoleResolver
	reqReads requestReadAuthorizer
	deleter  roleDeleter
	capGuard
}

// roleDeleter runs the transactional DeleteRole cascade (deleting a role plus every
// binding, grant-edge, and policy that references it, and revoking its active grants
// so live sessions are torn down). Backed by *accessrequest.Service; a narrow seam so
// the handler reuses the existing revoke/terminator machinery rather than reinventing
// live-session teardown. May be nil in tests that don't exercise deletion.
type roleDeleter interface {
	DeleteRoleCascade(ctx context.Context, actor, roleID uuid.UUID) error
}

// NewAccessServer constructs the AccessService implementation. reqReads authorizes
// request-scoped display reads (GetRoleDisplay) for callers who are party to a
// pending access request but lack the read capability; a nil reqReads disables that
// path (only the capability grants the read). deleter runs the DeleteRole cascade.
func NewAccessServer(q *gen.Queries, roles *authz.RoleResolver, a authz.Authorizer, reqReads requestReadAuthorizer, deleter roleDeleter) *AccessServer {
	return &AccessServer{q: q, roles: roles, reqReads: reqReads, deleter: deleter, capGuard: capGuard{authz: a, q: q}}
}

func toAccessRoleMsg(r gen.Role) *accessv1.Role {
	var caps []string
	_ = json.Unmarshal(r.Capabilities, &caps)
	return &accessv1.Role{
		Id:           r.ID.String(),
		Name:         r.Name,
		Capabilities: caps,
		FolderId:     pgUUIDToString(r.FolderID),
	}
}

// roleMsgWithPath returns the role message with folder_path populated (empty for global).
func (s *AccessServer) roleMsgWithPath(ctx context.Context, r gen.Role) (*accessv1.Role, error) {
	m := toAccessRoleMsg(r)
	if r.FolderID.Valid {
		fp, err := s.q.FolderPath(ctx, uuidFromPg(r.FolderID))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		m.FolderPath = fp
	}
	return m, nil
}

func toAccessRoleGrantMsg(g gen.RoleGrant) *accessv1.RoleGrant {
	return &accessv1.RoleGrant{
		Id:           g.ID.String(),
		RoleId:       g.RoleID.String(),
		SourceRoleId: g.SourceRoleID.String(),
		Via:          g.Via,
	}
}

func toRoleBindingMsg(b gen.RoleBinding) *accessv1.RoleBinding {
	return &accessv1.RoleBinding{
		Id:             b.ID.String(),
		RoleId:         b.RoleID.String(),
		ScopeFolderId:  pgUUIDToString(b.ScopeFolderID),
		ScopeAssetId:   pgUUIDToString(b.ScopeAssetID),
		SubjectUserId:  pgUUIDToString(b.SubjectUserID),
		SubjectGroupId: pgUUIDToString(b.SubjectGroupID),
	}
}

func toRequestPolicyMsg(r gen.RequestPolicy) *accessv1.RequestPolicy {
	return &accessv1.RequestPolicy{
		Id:                 r.ID.String(),
		RoleId:             r.RoleID.String(),
		ScopeFolderId:      pgUUIDToString(r.ScopeFolderID),
		ScopeAssetId:       pgUUIDToString(r.ScopeAssetID),
		RequiredApprovals:  r.RequiredApprovals,
		RequesterRoleId:    pgUUIDToString(r.RequesterRoleID),
		ApproverRoleId:     pgUUIDToString(r.ApproverRoleID),
		MaxDurationSeconds: intervalToSeconds(r.MaxDuration),
		Name:               r.Name.String,
	}
}

// pgText maps "" to a NULL pgtype.Text, else a valid one.
func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// secondsToInterval maps a non-negative seconds count to a pgtype.Interval.
// 0 → invalid (NULL); else a Microseconds-valued interval.
func secondsToInterval(seconds int64) pgtype.Interval {
	if seconds <= 0 {
		return pgtype.Interval{Valid: false}
	}
	return pgtype.Interval{Microseconds: seconds * 1_000_000, Valid: true}
}

// intervalToSeconds maps a pgtype.Interval back to whole seconds; invalid → 0.
// Months/Days are folded in using civil-day approximations (30d month, 24h day)
// so admin-configured caps expressed in those units round-trip sensibly.
func intervalToSeconds(iv pgtype.Interval) int64 {
	if !iv.Valid {
		return 0
	}
	const secPerDay = 86400
	return int64(iv.Months)*30*secPerDay + int64(iv.Days)*secPerDay + iv.Microseconds/1_000_000
}

func toPolicySubjectMsg(s gen.RequestPolicySubject) *accessv1.PolicySubject {
	return &accessv1.PolicySubject{
		Id:             s.ID.String(),
		PolicyId:       s.PolicyID.String(),
		Kind:           s.Kind,
		SubjectUserId:  pgUUIDToString(s.SubjectUserID),
		SubjectGroupId: pgUUIDToString(s.SubjectGroupID),
	}
}

// CreateRole creates a custom role (admin only).
func (s *AccessServer) CreateRole(ctx context.Context, req *connect.Request[accessv1.CreateRoleRequest]) (*connect.Response[accessv1.CreateRoleResponse], error) {
	capsJSON, err := json.Marshal(req.Msg.Capabilities)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	folderID, _, err := optUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	if err := s.requireCap(ctx, "access:role:create", scopeOfFolderID(folderID)); err != nil {
		return nil, err
	}
	r, err := s.q.CreateRole(ctx, gen.CreateRoleParams{Name: req.Msg.Name, FolderID: folderID, Capabilities: capsJSON})
	if err != nil {
		return nil, mapWriteErr(err)
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
		m := toAccessRoleMsg(rows[i])
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

// AddRoleGrant adds a role-rewrite rule "holding source_role_id CONFERS role_id"
// (admin only). Mirrors the DB constraints: same-object self-reference is
// rejected; a duplicate rule is AlreadyExists; an unknown role is InvalidArgument.
func (s *AccessServer) AddRoleGrant(ctx context.Context, req *connect.Request[accessv1.AddRoleGrantRequest]) (*connect.Response[accessv1.AddRoleGrantResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	sourceRoleID, err := uuid.Parse(req.Msg.SourceRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad source_role_id"))
	}
	scope, err := s.scopeOfRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:role:update", scope); err != nil {
		return nil, err
	}
	caps, err := s.roleCaps(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGrantable(ctx, caps, scope); err != nil {
		return nil, err
	}
	if req.Msg.Via == "same_object" && roleID == sourceRoleID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("same-object self-reference not allowed"))
	}
	g, err := s.q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: roleID, SourceRoleID: sourceRoleID, Via: req.Msg.Via})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.AddRoleGrantResponse{Grant: toAccessRoleGrantMsg(g)}), nil
}

// RemoveRoleGrant deletes a role-rewrite rule by id (admin only). Deleting a
// non-existent id is a no-op (gated by the capability at global scope). Removing
// a grant only REMOVES conferred authority (de-escalation), so no grantable
// subset check is required.
func (s *AccessServer) RemoveRoleGrant(ctx context.Context, req *connect.Request[accessv1.RemoveRoleGrantRequest]) (*connect.Response[accessv1.RemoveRoleGrantResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	g, err := s.q.GetRoleGrant(ctx, id)
	if err != nil {
		// Deleting a non-existent grant is a no-op. With no row to derive a scope
		// from we fail closed, requiring the capability globally before the no-op.
		if err := s.requireCap(ctx, "access:role:update", authz.GlobalScope()); err != nil {
			return nil, err
		}
		return connect.NewResponse(&accessv1.RemoveRoleGrantResponse{}), nil
	}
	scope, err := s.scopeOfRole(ctx, g.RoleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:role:update", scope); err != nil {
		return nil, err
	}
	if err := s.q.DeleteRoleGrant(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.RemoveRoleGrantResponse{}), nil
}

// ListRoleGrants lists the rewrite rules conferring role_id (admin only),
// ordered by (created_at DESC, id ASC).
func (s *AccessServer) ListRoleGrants(ctx context.Context, req *connect.Request[accessv1.ListRoleGrantsRequest]) (*connect.Response[accessv1.ListRoleGrantsResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scope, err := s.scopeOfRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:role:read", scope); err != nil {
		return nil, err
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListRoleGrantsParams{RoleID: roleID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRoleGrants(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRoleGrantsResponse{}
	for i := range rows {
		out.Grants = append(out.Grants, toAccessRoleGrantMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here created_at.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// containedInRoleSubtree enforces folder-scoped role containment: if the role is
// folder-scoped, the binding/policy scope (an asset's folder, or a folder directly)
// must lie within the role's folder subtree. Global roles (folder NULL) are
// unrestricted. A folder-scoped role with no scope at all is rejected.
func (s *AccessServer) containedInRoleSubtree(ctx context.Context, roleID uuid.UUID, scopeFolder, scopeAsset pgtype.UUID) error {
	role, err := s.q.GetRole(ctx, roleID)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	if !role.FolderID.Valid {
		return nil // global role: no containment
	}
	var target uuid.UUID
	switch {
	case scopeFolder.Valid:
		target = uuidFromPg(scopeFolder)
	case scopeAsset.Valid:
		a, err := s.q.GetAsset(ctx, uuidFromPg(scopeAsset))
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
		}
		target = a.FolderID
	default:
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("a folder-scoped role requires a scope within its folder subtree"))
	}
	// The role's folder must be an ancestor-or-self of the scope's folder.
	ancestors, err := s.q.FolderAncestorsAndSelf(ctx, target)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	roleFolder := uuidFromPg(role.FolderID)
	for _, a := range ancestors {
		if a == roleFolder {
			return nil
		}
	}
	return connect.NewError(connect.CodeFailedPrecondition, errors.New("role is scoped to a folder and can only be bound within its subtree"))
}

// CreateRoleBinding grants a role to a subject at a scope (admin only).
func (s *AccessServer) CreateRoleBinding(ctx context.Context, req *connect.Request[accessv1.CreateRoleBindingRequest]) (*connect.Response[accessv1.CreateRoleBindingResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, hasFolder, err := optUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, hasAsset, err := optUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	if hasFolder && hasAsset {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most one of scope_folder_id, scope_asset_id may be set"))
	}
	subjUser, hasUser, err := optUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, hasGroup, err := optUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	if hasUser == hasGroup {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of subject_user_id, subject_group_id is required"))
	}
	bindScope := scopeOfObject(scopeFolder, scopeAsset)
	if err := s.requireCap(ctx, "access:binding:create", bindScope); err != nil {
		return nil, err
	}
	caps, err := s.roleCaps(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGrantable(ctx, caps, bindScope); err != nil {
		return nil, err
	}
	if err := s.containedInRoleSubtree(ctx, roleID, scopeFolder, scopeAsset); err != nil {
		return nil, err
	}
	rb, err := s.q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        roleID,
		ScopeFolderID: scopeFolder, ScopeAssetID: scopeAsset,
		SubjectUserID: subjUser, SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.CreateRoleBindingResponse{Id: rb.ID.String()}), nil
}

// DeleteRoleBinding removes a binding (admin only). Loads the binding to derive
// its scope, so a missing id returns NotFound.
func (s *AccessServer) DeleteRoleBinding(ctx context.Context, req *connect.Request[accessv1.DeleteRoleBindingRequest]) (*connect.Response[accessv1.DeleteRoleBindingResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	scope, err := s.scopeOfBinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:binding:delete", scope); err != nil {
		return nil, err
	}
	if err := s.q.DeleteRoleBinding(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRoleBindingResponse{}), nil
}

// ListRoleBindings lists bindings matching the (all-optional) filters (admin only).
// Results are ordered by (created_at DESC, id) with keyset pagination.
func (s *AccessServer) ListRoleBindings(ctx context.Context, req *connect.Request[accessv1.ListRoleBindingsRequest]) (*connect.Response[accessv1.ListRoleBindingsResponse], error) {
	if err := s.requireCap(ctx, "access:binding:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	roleID, _, err := optUUID(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, _, err := optUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, _, err := optUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	subjUser, _, err := optUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, _, err := optUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListRoleBindingsParams{
		RoleID:         roleID,
		ScopeFolderID:  scopeFolder,
		ScopeAssetID:   scopeAsset,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
		Lim:            limit,
	}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRoleBindings(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRoleBindingsResponse{}
	for i := range rows {
		out.Bindings = append(out.Bindings, toRoleBindingMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here created_at — for tables ordered by a different column (e.g.
	// access_grants.granted_at) use that column instead.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// CreateRequestPolicy creates a JIT request policy for a role (admin only).
func (s *AccessServer) CreateRequestPolicy(ctx context.Context, req *connect.Request[accessv1.CreateRequestPolicyRequest]) (*connect.Response[accessv1.CreateRequestPolicyResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, hasFolder, err := optUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, hasAsset, err := optUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	// Both scopes set simultaneously is not allowed; both empty (role default) is fine.
	if hasFolder && hasAsset {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most one of scope_folder_id, scope_asset_id may be set"))
	}
	requesterRole, _, err := optUUID(req.Msg.RequesterRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad requester_role_id"))
	}
	approverRole, _, err := optUUID(req.Msg.ApproverRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad approver_role_id"))
	}
	policyScope := scopeOfObject(scopeFolder, scopeAsset)
	if err := s.requireCap(ctx, "access:policy:create", policyScope); err != nil {
		return nil, err
	}
	caps, err := s.roleCaps(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGrantable(ctx, caps, policyScope); err != nil {
		return nil, err
	}
	if err := s.containedInRoleSubtree(ctx, roleID, scopeFolder, scopeAsset); err != nil {
		return nil, err
	}
	policy, err := s.q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID:            roleID,
		ScopeFolderID:     scopeFolder,
		ScopeAssetID:      scopeAsset,
		RequiredApprovals: req.Msg.RequiredApprovals,
		ApproverRoleID:    approverRole,
		RequesterRoleID:   requesterRole,
		MaxDuration:       secondsToInterval(req.Msg.MaxDurationSeconds),
		Name:              pgText(strings.ToLower(req.Msg.GetName())),
	})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.CreateRequestPolicyResponse{Policy: toRequestPolicyMsg(policy)}), nil
}

// UpdateRequestPolicy updates a policy's approvals + role sources (admin only).
func (s *AccessServer) UpdateRequestPolicy(ctx context.Context, req *connect.Request[accessv1.UpdateRequestPolicyRequest]) (*connect.Response[accessv1.UpdateRequestPolicyResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	scope, err := s.scopeOfPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:policy:update", scope); err != nil {
		return nil, err
	}
	requesterRole, _, err := optUUID(req.Msg.RequesterRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad requester_role_id"))
	}
	approverRole, _, err := optUUID(req.Msg.ApproverRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad approver_role_id"))
	}
	policy, err := s.q.UpdateRequestPolicy(ctx, gen.UpdateRequestPolicyParams{
		ID:                id,
		RequiredApprovals: req.Msg.RequiredApprovals,
		ApproverRoleID:    approverRole,
		RequesterRoleID:   requesterRole,
		MaxDuration:       secondsToInterval(req.Msg.MaxDurationSeconds),
	})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.UpdateRequestPolicyResponse{Policy: toRequestPolicyMsg(policy)}), nil
}

// DeleteRequestPolicy removes a request policy (admin only).
func (s *AccessServer) DeleteRequestPolicy(ctx context.Context, req *connect.Request[accessv1.DeleteRequestPolicyRequest]) (*connect.Response[accessv1.DeleteRequestPolicyResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	scope, err := s.scopeOfPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:policy:delete", scope); err != nil {
		return nil, err
	}
	if err := s.q.DeleteRequestPolicy(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRequestPolicyResponse{}), nil
}

// ListRequestPolicies lists all request policies for a role (admin only),
// ordered by (created_at DESC, id ASC).
func (s *AccessServer) ListRequestPolicies(ctx context.Context, req *connect.Request[accessv1.ListRequestPoliciesRequest]) (*connect.Response[accessv1.ListRequestPoliciesResponse], error) {
	if err := s.requireCap(ctx, "access:policy:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListRequestPoliciesParams{RoleID: roleID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRequestPolicies(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRequestPoliciesResponse{}
	for i := range rows {
		out.Policies = append(out.Policies, toRequestPolicyMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here created_at.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// ResolvePolicy maps a (name, asset scope) to a policy id (admin only). NotFound if
// no policy of that name is scoped to that asset.
func (s *AccessServer) ResolvePolicy(ctx context.Context, req *connect.Request[accessv1.ResolvePolicyRequest]) (*connect.Response[accessv1.ResolvePolicyResponse], error) {
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "access:policy:read", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	p, err := s.q.GetPolicyByNameAndAsset(ctx, gen.GetPolicyByNameAndAssetParams{
		Name:         pgText(strings.ToLower(req.Msg.Name)),
		ScopeAssetID: pgUUID(assetID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such policy"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.ResolvePolicyResponse{PolicyId: p.ID.String()}), nil
}

// AddPolicySubject adds a requester/approver subject to a policy (admin only).
func (s *AccessServer) AddPolicySubject(ctx context.Context, req *connect.Request[accessv1.AddPolicySubjectRequest]) (*connect.Response[accessv1.AddPolicySubjectResponse], error) {
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
	}
	scope, err := s.scopeOfPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:policy:manage-subjects", scope); err != nil {
		return nil, err
	}
	subjUser, hasUser, err := optUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, hasGroup, err := optUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	if hasUser == hasGroup {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of subject_user_id, subject_group_id is required"))
	}
	ps, err := s.q.AddPolicySubject(ctx, gen.AddPolicySubjectParams{
		PolicyID:       policyID,
		Kind:           req.Msg.Kind,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.AddPolicySubjectResponse{Id: ps.ID.String()}), nil
}

// RemovePolicySubject removes a subject from a policy (admin only). Loads the
// subject to derive its scope, so a missing id returns NotFound.
func (s *AccessServer) RemovePolicySubject(ctx context.Context, req *connect.Request[accessv1.RemovePolicySubjectRequest]) (*connect.Response[accessv1.RemovePolicySubjectResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	ps, err := s.q.GetPolicySubject(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("policy subject not found"))
	}
	scope, err := s.scopeOfPolicy(ctx, ps.PolicyID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:policy:manage-subjects", scope); err != nil {
		return nil, err
	}
	if err := s.q.RemovePolicySubject(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.RemovePolicySubjectResponse{}), nil
}

// ListPolicySubjects lists the subjects attached to a policy (admin only),
// ordered by (created_at DESC, id ASC).
func (s *AccessServer) ListPolicySubjects(ctx context.Context, req *connect.Request[accessv1.ListPolicySubjectsRequest]) (*connect.Response[accessv1.ListPolicySubjectsResponse], error) {
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
	}
	scope, err := s.scopeOfPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:policy:read", scope); err != nil {
		return nil, err
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListPolicySubjectsParams{PolicyID: policyID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListPolicySubjects(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListPolicySubjectsResponse{}
	for i := range rows {
		out.Subjects = append(out.Subjects, toPolicySubjectMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here created_at.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
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
