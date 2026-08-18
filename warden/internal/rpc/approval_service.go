package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	approvalv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/approval/v1"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// ApprovalServer implements approvalv1connect.ApprovalServiceHandler.
type ApprovalServer struct {
	q        *gen.Queries
	resolver *approvals.Resolver
}

// NewApprovalServer constructs the ApprovalService implementation.
func NewApprovalServer(q *gen.Queries, resolver *approvals.Resolver) *ApprovalServer {
	return &ApprovalServer{q: q, resolver: resolver}
}

func toApprovalRuleMsg(r gen.ApprovalRule) *approvalv1.ApprovalRule {
	return &approvalv1.ApprovalRule{
		Id:                r.ID.String(),
		RoleId:            r.RoleID.String(),
		ScopeFolderId:     pgUUIDToString(r.ScopeFolderID),
		ScopeAssetId:      pgUUIDToString(r.ScopeAssetID),
		RequiredApprovals: r.RequiredApprovals,
		ApproverRoleId:    pgUUIDToString(r.ApproverRoleID),
	}
}

// CreateApprovalRule creates an approval rule for a role (admin only).
func (s *ApprovalServer) CreateApprovalRule(ctx context.Context, req *connect.Request[approvalv1.CreateApprovalRuleRequest]) (*connect.Response[approvalv1.CreateApprovalRuleResponse], error) {
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
	approverRole, _, err := optUUID(req.Msg.ApproverRoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad approver_role_id"))
	}
	rule, err := s.q.CreateApprovalRule(ctx, gen.CreateApprovalRuleParams{
		RoleID:            roleID,
		ScopeFolderID:     scopeFolder,
		ScopeAssetID:      scopeAsset,
		RequiredApprovals: req.Msg.RequiredApprovals,
		ApproverRoleID:    approverRole,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&approvalv1.CreateApprovalRuleResponse{Rule: toApprovalRuleMsg(rule)}), nil
}

// DeleteApprovalRule removes an approval rule (admin only).
func (s *ApprovalServer) DeleteApprovalRule(ctx context.Context, req *connect.Request[approvalv1.DeleteApprovalRuleRequest]) (*connect.Response[approvalv1.DeleteApprovalRuleResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteApprovalRule(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&approvalv1.DeleteApprovalRuleResponse{}), nil
}

// ListApprovalRules lists all approval rules for a role (admin only).
func (s *ApprovalServer) ListApprovalRules(ctx context.Context, req *connect.Request[approvalv1.ListApprovalRulesRequest]) (*connect.Response[approvalv1.ListApprovalRulesResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	rows, err := s.q.ListApprovalRulesForRole(ctx, roleID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &approvalv1.ListApprovalRulesResponse{}
	for i := range rows {
		out.Rules = append(out.Rules, toApprovalRuleMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// AddRuleApprover adds an approver subject to a rule (admin only).
func (s *ApprovalServer) AddRuleApprover(ctx context.Context, req *connect.Request[approvalv1.AddRuleApproverRequest]) (*connect.Response[approvalv1.AddRuleApproverResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	ruleID, err := uuid.Parse(req.Msg.RuleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad rule_id"))
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
	ra, err := s.q.AddRuleApprover(ctx, gen.AddRuleApproverParams{
		RuleID:         ruleID,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&approvalv1.AddRuleApproverResponse{Id: ra.ID.String()}), nil
}

// RemoveRuleApprover removes an approver from a rule (admin only).
func (s *ApprovalServer) RemoveRuleApprover(ctx context.Context, req *connect.Request[approvalv1.RemoveRuleApproverRequest]) (*connect.Response[approvalv1.RemoveRuleApproverResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteRuleApprover(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&approvalv1.RemoveRuleApproverResponse{}), nil
}

// ResolveApproval returns the effective approval rule for a (role, asset) pair (admin only).
func (s *ApprovalServer) ResolveApproval(ctx context.Context, req *connect.Request[approvalv1.ResolveApprovalRequest]) (*connect.Response[approvalv1.ResolveApprovalResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	rule, err := s.resolver.EffectiveRule(ctx, roleID, assetID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if rule == nil {
		return connect.NewResponse(&approvalv1.ResolveApprovalResponse{Requestable: false}), nil
	}
	approverRoleID := ""
	if rule.ApproverRoleID != uuid.Nil {
		approverRoleID = rule.ApproverRoleID.String()
	}
	return connect.NewResponse(&approvalv1.ResolveApprovalResponse{
		Requestable:       true,
		RequiredApprovals: int32(rule.RequiredApprovals), //nolint:gosec // value is bounded 1-20 by proto validation
		ApproverRoleId:    approverRoleID,
	}), nil
}
