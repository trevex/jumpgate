package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// AccessServer implements accessv1connect.AccessServiceHandler: all authorization
// configuration (roles, grants, standing bindings, request policies) plus the
// admin-or-self ExplainRole introspection.
type AccessServer struct {
	q     *gen.Queries
	roles *authz.RoleResolver
}

// NewAccessServer constructs the AccessService implementation.
func NewAccessServer(q *gen.Queries, roles *authz.RoleResolver) *AccessServer {
	return &AccessServer{q: q, roles: roles}
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
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	capsJSON, err := json.Marshal(req.Msg.Capabilities)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	folderID, _, err := optUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	r, err := s.q.CreateRole(ctx, gen.CreateRoleParams{Name: req.Msg.Name, FolderID: folderID, Capabilities: capsJSON})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.CreateRoleResponse{Role: toAccessRoleMsg(r)}), nil
}

// ListRoles lists roles (admin only).
func (s *AccessServer) ListRoles(ctx context.Context, req *connect.Request[accessv1.ListRolesRequest]) (*connect.Response[accessv1.ListRolesResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	limit := req.Msg.PageSize
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	after := uuid.Nil
	if req.Msg.PageToken != "" {
		id, err := uuid.Parse(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
		}
		after = id
	}
	rows, err := s.q.ListRoles(ctx, gen.ListRolesParams{Column1: after, Limit: limit})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRolesResponse{}
	for i := range rows {
		out.Roles = append(out.Roles, toAccessRoleMsg(rows[i]))
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// GetRole fetches a single role by id (admin only).
func (s *AccessServer) GetRole(ctx context.Context, req *connect.Request[accessv1.GetRoleRequest]) (*connect.Response[accessv1.GetRoleResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	r, err := s.q.GetRole(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	return connect.NewResponse(&accessv1.GetRoleResponse{Role: toAccessRoleMsg(r)}), nil
}

// AddRoleGrant adds a role-rewrite rule "holding source_role_id CONFERS role_id"
// (admin only). Mirrors the DB constraints: same-object self-reference is
// rejected; a duplicate rule is AlreadyExists; an unknown role is InvalidArgument.
func (s *AccessServer) AddRoleGrant(ctx context.Context, req *connect.Request[accessv1.AddRoleGrantRequest]) (*connect.Response[accessv1.AddRoleGrantResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	sourceRoleID, err := uuid.Parse(req.Msg.SourceRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad source_role_id"))
	}
	if req.Msg.Via == "same_object" && roleID == sourceRoleID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("same-object self-reference not allowed"))
	}
	g, err := s.q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: roleID, SourceRoleID: sourceRoleID, Via: req.Msg.Via})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgerrcodeUniqueViolation:
				return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("role grant already exists"))
			case pgerrcodeForeignKeyViolation:
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown role"))
			case pgerrcodeCheckViolation:
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("role grant violates constraint"))
			}
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.AddRoleGrantResponse{Grant: toAccessRoleGrantMsg(g)}), nil
}

// RemoveRoleGrant deletes a role-rewrite rule by id (admin only). Deleting a
// non-existent id is a no-op.
func (s *AccessServer) RemoveRoleGrant(ctx context.Context, req *connect.Request[accessv1.RemoveRoleGrantRequest]) (*connect.Response[accessv1.RemoveRoleGrantResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteRoleGrant(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.RemoveRoleGrantResponse{}), nil
}

// ListRoleGrants lists the rewrite rules conferring role_id (admin only).
func (s *AccessServer) ListRoleGrants(ctx context.Context, req *connect.Request[accessv1.ListRoleGrantsRequest]) (*connect.Response[accessv1.ListRoleGrantsResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	rows, err := s.q.ListRoleGrants(ctx, roleID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRoleGrantsResponse{}
	for i := range rows {
		out.Grants = append(out.Grants, toAccessRoleGrantMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// CreateRoleBinding grants a role to a subject at a scope (admin only).
func (s *AccessServer) CreateRoleBinding(ctx context.Context, req *connect.Request[accessv1.CreateRoleBindingRequest]) (*connect.Response[accessv1.CreateRoleBindingResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
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
	if hasFolder == hasAsset { // both set or both unset
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of scope_folder_id, scope_asset_id is required"))
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

// DeleteRoleBinding removes a binding (admin only). Deleting a non-existent id is a no-op.
func (s *AccessServer) DeleteRoleBinding(ctx context.Context, req *connect.Request[accessv1.DeleteRoleBindingRequest]) (*connect.Response[accessv1.DeleteRoleBindingResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteRoleBinding(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRoleBindingResponse{}), nil
}

// ListRoleBindings lists bindings matching the (all-optional) filters (admin only).
func (s *AccessServer) ListRoleBindings(ctx context.Context, req *connect.Request[accessv1.ListRoleBindingsRequest]) (*connect.Response[accessv1.ListRoleBindingsResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
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
	rows, err := s.q.ListRoleBindings(ctx, gen.ListRoleBindingsParams{
		RoleID:         roleID,
		ScopeFolderID:  scopeFolder,
		ScopeAssetID:   scopeAsset,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRoleBindingsResponse{}
	for i := range rows {
		out.Bindings = append(out.Bindings, toRoleBindingMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// CreateRequestPolicy creates a JIT request policy for a role (admin only).
func (s *AccessServer) CreateRequestPolicy(ctx context.Context, req *connect.Request[accessv1.CreateRequestPolicyRequest]) (*connect.Response[accessv1.CreateRequestPolicyResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
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
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
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
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteRequestPolicy(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRequestPolicyResponse{}), nil
}

// ListRequestPolicies lists all request policies for a role (admin only).
func (s *AccessServer) ListRequestPolicies(ctx context.Context, req *connect.Request[accessv1.ListRequestPoliciesRequest]) (*connect.Response[accessv1.ListRequestPoliciesResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	rows, err := s.q.ListRequestPoliciesForRole(ctx, roleID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRequestPoliciesResponse{}
	for i := range rows {
		out.Policies = append(out.Policies, toRequestPolicyMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// ResolvePolicy maps a (name, asset scope) to a policy id (admin only). NotFound if
// no policy of that name is scoped to that asset.
func (s *AccessServer) ResolvePolicy(ctx context.Context, req *connect.Request[accessv1.ResolvePolicyRequest]) (*connect.Response[accessv1.ResolvePolicyResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
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
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
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

// RemovePolicySubject removes a subject from a policy (admin only).
func (s *AccessServer) RemovePolicySubject(ctx context.Context, req *connect.Request[accessv1.RemovePolicySubjectRequest]) (*connect.Response[accessv1.RemovePolicySubjectResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.RemovePolicySubject(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.RemovePolicySubjectResponse{}), nil
}

// ListPolicySubjects lists the subjects attached to a policy (admin only).
func (s *AccessServer) ListPolicySubjects(ctx context.Context, req *connect.Request[accessv1.ListPolicySubjectsRequest]) (*connect.Response[accessv1.ListPolicySubjectsResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	policyID, err := uuid.Parse(req.Msg.PolicyId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad policy_id"))
	}
	rows, err := s.q.ListPolicySubjects(ctx, policyID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListPolicySubjectsResponse{}
	for i := range rows {
		out.Subjects = append(out.Subjects, toPolicySubjectMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
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
	if !caller.IsAdmin && userID != caller.ID {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("may only explain your own access"))
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
