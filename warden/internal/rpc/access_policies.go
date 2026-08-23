package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

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
