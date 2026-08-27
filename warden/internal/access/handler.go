package access

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Handler adapts the access Service to the generated AccessServiceHandler interface:
// it extracts the caller from context, validates + parses proto, applies the
// capability gate (scope-from-request or scope-from-a-loaded-row via the guard),
// calls one service method — the entangled invariants (no-escalation subset,
// containment, the request-party display path) stay in the service, which takes the
// caller explicitly — and maps the domain result back to proto.
type Handler struct {
	svc   *Service
	guard apiguard.Guard
}

// NewHandler constructs the access transport Handler over svc and guard.
func NewHandler(svc *Service, guard apiguard.Guard) *Handler {
	return &Handler{svc: svc, guard: guard}
}

// caller extracts the authenticated user's id from ctx. In real requests the auth
// interceptor guarantees a user; an in-process caller without one is Unauthenticated.
func caller(ctx context.Context) (uuid.UUID, error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return u.ID, nil
}

// ── proto mapping ────────────────────────────────────────────────────────────

func toAccessRoleMsg(r sqlc.Role, caps []string) *accessv1.Role {
	return &accessv1.Role{
		Id:           r.ID.String(),
		Name:         r.Name,
		Capabilities: caps,
		FolderId:     pgconv.UUIDString(r.FolderID),
	}
}

// roleMsg renders a RoleResult as an access Role message with folder_path populated.
func roleMsg(res RoleResult) *accessv1.Role {
	m := toAccessRoleMsg(res.Role, res.Caps)
	m.FolderPath = res.FolderPath
	return m
}

func toAccessRoleGrantMsg(g sqlc.RoleGrant) *accessv1.RoleGrant {
	return &accessv1.RoleGrant{
		Id:           g.ID.String(),
		RoleId:       g.RoleID.String(),
		SourceRoleId: g.SourceRoleID.String(),
		Via:          g.Via,
	}
}

func toRoleBindingMsg(b sqlc.RoleBinding) *accessv1.RoleBinding {
	return &accessv1.RoleBinding{
		Id:             b.ID.String(),
		RoleId:         b.RoleID.String(),
		ScopeFolderId:  pgconv.UUIDString(b.ScopeFolderID),
		ScopeAssetId:   pgconv.UUIDString(b.ScopeAssetID),
		SubjectUserId:  pgconv.UUIDString(b.SubjectUserID),
		SubjectGroupId: pgconv.UUIDString(b.SubjectGroupID),
	}
}

func toRequestPolicyMsg(r sqlc.RequestPolicy) *accessv1.RequestPolicy {
	return &accessv1.RequestPolicy{
		Id:                 r.ID.String(),
		RoleId:             r.RoleID.String(),
		ScopeFolderId:      pgconv.UUIDString(r.ScopeFolderID),
		ScopeAssetId:       pgconv.UUIDString(r.ScopeAssetID),
		RequiredApprovals:  r.RequiredApprovals,
		RequesterRoleId:    pgconv.UUIDString(r.RequesterRoleID),
		ApproverRoleId:     pgconv.UUIDString(r.ApproverRoleID),
		MaxDurationSeconds: intervalToSeconds(r.MaxDuration),
		Name:               r.Name.String,
	}
}

func toPolicySubjectMsg(s sqlc.RequestPolicySubject) *accessv1.PolicySubject {
	return &accessv1.PolicySubject{
		Id:             s.ID.String(),
		PolicyId:       s.PolicyID.String(),
		Kind:           s.Kind,
		SubjectUserId:  pgconv.UUIDString(s.SubjectUserID),
		SubjectGroupId: pgconv.UUIDString(s.SubjectGroupID),
	}
}

// ── roles ────────────────────────────────────────────────────────────────────

// CreateRole gates on access:role:create at the role's (request) folder scope, then
// delegates to the service (role + capabilities in one transaction).
func (h *Handler) CreateRole(ctx context.Context, req *connect.Request[accessv1.CreateRoleRequest]) (*connect.Response[accessv1.CreateRoleResponse], error) {
	folderID, _, err := pgconv.OptUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:role:create", apiguard.ScopeOfFolderID(folderID)); err != nil {
		return nil, err
	}
	res, err := h.svc.CreateRole(ctx, req.Msg.Name, folderID, req.Msg.Capabilities)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CreateRoleResponse{Role: roleMsg(res)}), nil
}

// ResolveRole resolves uuid | name (global) | <role>.<folder-path> (scoped) to a role
// id (existence-hidden by the service's read gate), echoing the canonical path.
func (h *Handler) ResolveRole(ctx context.Context, req *connect.Request[accessv1.ResolveRoleRequest]) (*connect.Response[accessv1.ResolveRoleResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.ResolveRole(ctx, c, req.Msg.Ref)
	if err != nil {
		return nil, err
	}
	path := res.Role.Name
	if res.FolderPath != "" {
		path = res.Role.Name + "." + res.FolderPath
	}
	return connect.NewResponse(&accessv1.ResolveRoleResponse{RoleId: res.Role.ID.String(), Path: path}), nil
}

// ListRoles browses the caller's visible roles under a parent (default root).
func (h *Handler) ListRoles(ctx context.Context, req *connect.Request[accessv1.ListRolesRequest]) (*connect.Response[accessv1.ListRolesResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListRoles(ctx, c, req.Msg.Parent, req.Msg.Cascade, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListRolesResponse{NextPageToken: next}
	for _, r := range rows {
		out.Roles = append(out.Roles, roleMsg(r))
	}
	return connect.NewResponse(out), nil
}

// GetRole fetches a single role by id (access:role:read at the role's folder scope).
func (h *Handler) GetRole(ctx context.Context, req *connect.Request[accessv1.GetRoleRequest]) (*connect.Response[accessv1.GetRoleResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.GetRole(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetRoleResponse{Role: roleMsg(res)}), nil
}

// DeleteRole gates on access:role:delete at the role's folder scope, then delegates
// the transactional cascade to the service (via the roleDeleter). A missing role is
// NotFound.
func (h *Handler) DeleteRole(ctx context.Context, req *connect.Request[accessv1.DeleteRoleRequest]) (*connect.Response[accessv1.DeleteRoleResponse], error) {
	id, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfRole(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:role:delete", scope); err != nil {
		return nil, err
	}
	if err := h.svc.DeleteRole(ctx, c, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.DeleteRoleResponse{}), nil
}

// GetRoleDisplay returns a role's decision context (name, folder path, and the
// capabilities it grants). Authorized by access:role:read OR the caller being party
// to a pending access request referencing the role.
func (h *Handler) GetRoleDisplay(ctx context.Context, req *connect.Request[accessv1.GetRoleDisplayRequest]) (*connect.Response[accessv1.GetRoleDisplayResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.GetRoleDisplay(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetRoleDisplayResponse{Role: &accessv1.RoleDisplay{
		Id:           res.Role.ID.String(),
		Name:         res.Role.Name,
		FolderPath:   res.FolderPath,
		Capabilities: res.Caps,
	}}), nil
}

// GetRoleAccess returns the caller's management capabilities on one role.
func (h *Handler) GetRoleAccess(ctx context.Context, req *connect.Request[accessv1.GetRoleAccessRequest]) (*connect.Response[accessv1.GetRoleAccessResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	caps, err := h.svc.GetRoleAccess(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetRoleAccessResponse{Capabilities: caps}), nil
}

// ExplainRole enumerates every derivation by which a user holds a role on an asset.
// Admins may explain anyone; a non-admin may only explain themselves.
func (h *Handler) ExplainRole(ctx context.Context, req *connect.Request[accessv1.ExplainRoleRequest]) (*connect.Response[accessv1.ExplainRoleResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	// Callers may always explain their own access; explaining another user's access
	// requires the management read cap (admins hold ** globally).
	if userID != c {
		if err := h.guard.RequireCap(ctx, c, "access:role:read", authz.GlobalScope()); err != nil {
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
	holds, paths, err := h.svc.ExplainRole(ctx, userID, roleID, assetID)
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

// ── bindings ──────────────────────────────────────────────────────────────────

// CreateRoleBinding grants a role to a subject at a scope. Gates on
// access:binding:create; the service enforces no-escalation + containment.
func (h *Handler) CreateRoleBinding(ctx context.Context, req *connect.Request[accessv1.CreateRoleBindingRequest]) (*connect.Response[accessv1.CreateRoleBindingResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, hasFolder, err := pgconv.OptUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, hasAsset, err := pgconv.OptUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	if hasFolder && hasAsset {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most one of scope_folder_id, scope_asset_id may be set"))
	}
	subjUser, hasUser, err := pgconv.OptUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, hasGroup, err := pgconv.OptUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	if hasUser == hasGroup {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of subject_user_id, subject_group_id is required"))
	}
	bindScope := apiguard.ScopeOfObject(scopeFolder, scopeAsset)
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:binding:create", bindScope); err != nil {
		return nil, err
	}
	rb, err := h.svc.CreateRoleBinding(ctx, c, roleID, scopeFolder, scopeAsset, subjUser, subjGroup, bindScope)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CreateRoleBindingResponse{Id: rb.ID.String()}), nil
}

// DeleteRoleBinding removes a binding. Loads the binding to derive its scope, so a
// missing id returns NotFound.
func (h *Handler) DeleteRoleBinding(ctx context.Context, req *connect.Request[accessv1.DeleteRoleBindingRequest]) (*connect.Response[accessv1.DeleteRoleBindingResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfBinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:binding:delete", scope); err != nil {
		return nil, err
	}
	if err := h.svc.DeleteRoleBinding(ctx, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.DeleteRoleBindingResponse{}), nil
}

// ListRoleBindings lists bindings matching the (all-optional) filters, authorized by
// access:binding:read at the QUERIED scope (asset > folder > global).
func (h *Handler) ListRoleBindings(ctx context.Context, req *connect.Request[accessv1.ListRoleBindingsRequest]) (*connect.Response[accessv1.ListRoleBindingsResponse], error) {
	roleID, _, err := pgconv.OptUUID(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, _, err := pgconv.OptUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, _, err := pgconv.OptUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	// Scope the cap check to the pinned object (asset > folder > global).
	if err := h.guard.RequireCap(ctx, c, "access:binding:read", apiguard.ScopeOfObject(scopeFolder, scopeAsset)); err != nil {
		return nil, err
	}
	subjUser, _, err := pgconv.OptUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, _, err := pgconv.OptUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	rows, next, err := h.svc.ListRoleBindings(ctx, roleID, scopeFolder, scopeAsset, subjUser, subjGroup, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListRoleBindingsResponse{NextPageToken: next}
	for i := range rows {
		out.Bindings = append(out.Bindings, toRoleBindingMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ── policies ──────────────────────────────────────────────────────────────────

// CreateRequestPolicy creates a JIT request policy for a role. Gates on
// access:policy:create; the service enforces no-escalation + containment.
func (h *Handler) CreateRequestPolicy(ctx context.Context, req *connect.Request[accessv1.CreateRequestPolicyRequest]) (*connect.Response[accessv1.CreateRequestPolicyResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, hasFolder, err := pgconv.OptUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, hasAsset, err := pgconv.OptUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	// Both scopes set simultaneously is not allowed; both empty (role default) is fine.
	if hasFolder && hasAsset {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most one of scope_folder_id, scope_asset_id may be set"))
	}
	requesterRole, _, err := pgconv.OptUUID(req.Msg.RequesterRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad requester_role_id"))
	}
	approverRole, _, err := pgconv.OptUUID(req.Msg.ApproverRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad approver_role_id"))
	}
	policyScope := apiguard.ScopeOfObject(scopeFolder, scopeAsset)
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:create", policyScope); err != nil {
		return nil, err
	}
	policy, err := h.svc.CreateRequestPolicy(ctx, c, CreateRequestPolicyInput{
		RoleID:             roleID,
		ScopeFolder:        scopeFolder,
		ScopeAsset:         scopeAsset,
		RequiredApprovals:  req.Msg.RequiredApprovals,
		ApproverRole:       approverRole,
		RequesterRole:      requesterRole,
		MaxDurationSeconds: req.Msg.MaxDurationSeconds,
		Name:               strings.ToLower(req.Msg.GetName()),
	}, policyScope)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CreateRequestPolicyResponse{Policy: toRequestPolicyMsg(policy)}), nil
}

// UpdateRequestPolicy updates a policy's approvals + role sources.
func (h *Handler) UpdateRequestPolicy(ctx context.Context, req *connect.Request[accessv1.UpdateRequestPolicyRequest]) (*connect.Response[accessv1.UpdateRequestPolicyResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:update", scope); err != nil {
		return nil, err
	}
	requesterRole, _, err := pgconv.OptUUID(req.Msg.RequesterRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad requester_role_id"))
	}
	approverRole, _, err := pgconv.OptUUID(req.Msg.ApproverRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad approver_role_id"))
	}
	policy, err := h.svc.UpdateRequestPolicy(ctx, id, req.Msg.RequiredApprovals, approverRole, requesterRole, req.Msg.MaxDurationSeconds)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.UpdateRequestPolicyResponse{Policy: toRequestPolicyMsg(policy)}), nil
}

// DeleteRequestPolicy removes a request policy.
func (h *Handler) DeleteRequestPolicy(ctx context.Context, req *connect.Request[accessv1.DeleteRequestPolicyRequest]) (*connect.Response[accessv1.DeleteRequestPolicyResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:delete", scope); err != nil {
		return nil, err
	}
	if err := h.svc.DeleteRequestPolicy(ctx, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.DeleteRequestPolicyResponse{}), nil
}

// ListRequestPolicies lists all request policies for a role (global read gate).
func (h *Handler) ListRequestPolicies(ctx context.Context, req *connect.Request[accessv1.ListRequestPoliciesRequest]) (*connect.Response[accessv1.ListRequestPoliciesResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	rows, next, err := h.svc.ListRequestPolicies(ctx, roleID, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListRequestPoliciesResponse{NextPageToken: next}
	for i := range rows {
		out.Policies = append(out.Policies, toRequestPolicyMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ListPoliciesForAsset lists the request policies scoped to an asset (global read gate).
func (h *Handler) ListPoliciesForAsset(ctx context.Context, req *connect.Request[accessv1.ListPoliciesForAssetRequest]) (*connect.Response[accessv1.ListPoliciesForAssetResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	rows, next, err := h.svc.ListPoliciesForAsset(ctx, assetID, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListPoliciesForAssetResponse{NextPageToken: next}
	for i := range rows {
		out.Policies = append(out.Policies, toRequestPolicyMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ListPoliciesForGroup lists the request policies a group is a subject of (global read gate).
func (h *Handler) ListPoliciesForGroup(ctx context.Context, req *connect.Request[accessv1.ListPoliciesForGroupRequest]) (*connect.Response[accessv1.ListPoliciesForGroupResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	groupID, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	rows, next, err := h.svc.ListPoliciesForGroup(ctx, groupID, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListPoliciesForGroupResponse{NextPageToken: next}
	for i := range rows {
		out.Policies = append(out.Policies, toRequestPolicyMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ResolvePolicy maps a (name, asset scope) to a policy id. NotFound if no policy of
// that name is scoped to that asset.
func (h *Handler) ResolvePolicy(ctx context.Context, req *connect.Request[accessv1.ResolvePolicyRequest]) (*connect.Response[accessv1.ResolvePolicyResponse], error) {
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:read", authz.AssetScope(assetID)); err != nil {
		return nil, err
	}
	p, err := h.svc.ResolvePolicy(ctx, strings.ToLower(req.Msg.Name), assetID)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ResolvePolicyResponse{PolicyId: p.ID.String()}), nil
}

// AddPolicySubject adds a requester/approver subject to a policy.
func (h *Handler) AddPolicySubject(ctx context.Context, req *connect.Request[accessv1.AddPolicySubjectRequest]) (*connect.Response[accessv1.AddPolicySubjectResponse], error) {
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:manage-subjects", scope); err != nil {
		return nil, err
	}
	subjUser, hasUser, err := pgconv.OptUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, hasGroup, err := pgconv.OptUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	if hasUser == hasGroup {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of subject_user_id, subject_group_id is required"))
	}
	ps, err := h.svc.AddPolicySubject(ctx, policyID, req.Msg.Kind, subjUser, subjGroup)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.AddPolicySubjectResponse{Id: ps.ID.String()}), nil
}

// RemovePolicySubject removes a subject from a policy. Loads the subject to derive its
// scope, so a missing id returns NotFound.
func (h *Handler) RemovePolicySubject(ctx context.Context, req *connect.Request[accessv1.RemovePolicySubjectRequest]) (*connect.Response[accessv1.RemovePolicySubjectResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := h.guard.Q.GetPolicySubject(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("policy subject not found"))
	}
	scope, err := h.guard.ScopeOfPolicy(ctx, ps.PolicyID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:manage-subjects", scope); err != nil {
		return nil, err
	}
	if err := h.svc.RemovePolicySubject(ctx, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.RemovePolicySubjectResponse{}), nil
}

// ListPolicySubjects lists the subjects attached to a policy.
func (h *Handler) ListPolicySubjects(ctx context.Context, req *connect.Request[accessv1.ListPolicySubjectsRequest]) (*connect.Response[accessv1.ListPolicySubjectsResponse], error) {
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfPolicy(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:policy:read", scope); err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListPolicySubjects(ctx, policyID, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListPolicySubjectsResponse{NextPageToken: next}
	for i := range rows {
		out.Subjects = append(out.Subjects, toPolicySubjectMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ── role grants ────────────────────────────────────────────────────────────────

// AddRoleGrant adds a role-rewrite rule "holding source_role_id CONFERS role_id".
// Gates on access:role:update at the RECIPIENT role's scope; the service enforces the
// no-escalation subset rule against the RECIPIENT role's capabilities.
func (h *Handler) AddRoleGrant(ctx context.Context, req *connect.Request[accessv1.AddRoleGrantRequest]) (*connect.Response[accessv1.AddRoleGrantResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	sourceRoleID, err := uuid.Parse(req.Msg.SourceRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad source_role_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:role:update", scope); err != nil {
		return nil, err
	}
	g, err := h.svc.AddRoleGrant(ctx, c, roleID, sourceRoleID, req.Msg.Via, scope)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.AddRoleGrantResponse{Grant: toAccessRoleGrantMsg(g)}), nil
}

// RemoveRoleGrant deletes a role-rewrite rule by id. Deleting a non-existent id is a
// no-op (gated by the capability at global scope). Removing a grant only REMOVES
// conferred authority (de-escalation), so no grantable subset check is required.
func (h *Handler) RemoveRoleGrant(ctx context.Context, req *connect.Request[accessv1.RemoveRoleGrantRequest]) (*connect.Response[accessv1.RemoveRoleGrantResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	g, err := h.guard.Q.GetRoleGrant(ctx, id)
	if err != nil {
		// Deleting a non-existent grant is a no-op. With no row to derive a scope from
		// we fail closed, requiring the capability globally before the no-op.
		if err := h.guard.RequireCap(ctx, c, "access:role:update", authz.GlobalScope()); err != nil {
			return nil, err
		}
		return connect.NewResponse(&accessv1.RemoveRoleGrantResponse{}), nil
	}
	scope, err := h.guard.ScopeOfRole(ctx, g.RoleID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "access:role:update", scope); err != nil {
		return nil, err
	}
	if err := h.svc.RemoveRoleGrant(ctx, id); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.RemoveRoleGrantResponse{}), nil
}

// ListRoleGrants lists the rewrite rules conferring role_id.
func (h *Handler) ListRoleGrants(ctx context.Context, req *connect.Request[accessv1.ListRoleGrantsRequest]) (*connect.Response[accessv1.ListRoleGrantsResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireReadCap(ctx, c, "access:role:read", scope); err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListRoleGrants(ctx, roleID, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListRoleGrantsResponse{NextPageToken: next}
	for i := range rows {
		out.Grants = append(out.Grants, toAccessRoleGrantMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}
