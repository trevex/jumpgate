package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/auth"
)

// AccessRequestServer implements accessrequestv1connect.AccessRequestServiceHandler:
// the JIT access-request runtime. RequestAccess/Approve/Deny/Revoke + access_grants
// + reaper are M3c; currently only ResolveApproval is implemented.
type AccessRequestServer struct {
	resolver *approvals.Resolver
}

// NewAccessRequestServer constructs the AccessRequestService implementation.
func NewAccessRequestServer(resolver *approvals.Resolver) *AccessRequestServer {
	return &AccessRequestServer{resolver: resolver}
}

// ResolveApproval returns the effective request policy for a (role, asset) pair (admin only).
func (s *AccessRequestServer) ResolveApproval(ctx context.Context, req *connect.Request[accessrequestv1.ResolveApprovalRequest]) (*connect.Response[accessrequestv1.ResolveApprovalResponse], error) {
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
		return connect.NewResponse(&accessrequestv1.ResolveApprovalResponse{Requestable: false}), nil
	}
	approverRoleID := ""
	if rule.ApproverRoleID != uuid.Nil {
		approverRoleID = rule.ApproverRoleID.String()
	}
	return connect.NewResponse(&accessrequestv1.ResolveApprovalResponse{
		Requestable:       true,
		RequiredApprovals: int32(rule.RequiredApprovals), //nolint:gosec // value is bounded 1-20 by proto validation
		ApproverRoleId:    approverRoleID,
	}), nil
}
