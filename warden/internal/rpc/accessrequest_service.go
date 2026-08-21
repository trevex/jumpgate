package rpc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// AccessRequestServer implements accessrequestv1connect.AccessRequestServiceHandler:
// the JIT access-request runtime. ResolveApproval is admin introspection; the
// request/approve/deny/cancel/list surface is authenticated and delegates all
// per-action authorization to the domain Service.
type AccessRequestServer struct {
	resolver *approvals.Resolver
	svc      *accessrequest.Service
	capGuard
}

// NewAccessRequestServer constructs the AccessRequestService implementation.
func NewAccessRequestServer(resolver *approvals.Resolver, svc *accessrequest.Service, a authz.Authorizer, q *gen.Queries) *AccessRequestServer {
	return &AccessRequestServer{resolver: resolver, svc: svc, capGuard: capGuard{authz: a, q: q}}
}

// mapAccessRequestErr maps a domain sentinel to a Connect error.
func mapAccessRequestErr(err error) error {
	switch {
	case errors.Is(err, accessrequest.ErrNotEligible):
		// Existence-hiding: an ineligible requester learns nothing about the policy.
		return connect.NewError(connect.CodeNotFound, errors.New("no requestable access"))
	case errors.Is(err, accessrequest.ErrNotRequestable):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("role is not JIT-requestable on this asset"))
	case errors.Is(err, accessrequest.ErrAlreadyActive):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("role is already active on this asset"))
	case errors.Is(err, accessrequest.ErrDuplicatePending):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("a pending request already exists"))
	case errors.Is(err, accessrequest.ErrNotPending):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("request is not pending"))
	case errors.Is(err, accessrequest.ErrNotApprover):
		return connect.NewError(connect.CodePermissionDenied, errors.New("not an approver for this request"))
	case errors.Is(err, accessrequest.ErrSelfApprove):
		return connect.NewError(connect.CodePermissionDenied, errors.New("cannot approve your own request"))
	case errors.Is(err, accessrequest.ErrAlreadyVoted):
		return connect.NewError(connect.CodeAlreadyExists, errors.New("already voted on this request"))
	case errors.Is(err, accessrequest.ErrNotRequester):
		return connect.NewError(connect.CodePermissionDenied, errors.New("not the requester"))
	case errors.Is(err, accessrequest.ErrGrantNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("grant not found"))
	case errors.Is(err, accessrequest.ErrRevokeForbidden):
		return connect.NewError(connect.CodePermissionDenied, errors.New("not permitted to revoke this grant"))
	case errors.Is(err, accessrequest.ErrGrantInactive):
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("grant is already inactive"))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func toAccessRequestMsg(r accessrequest.Request) *accessrequestv1.AccessRequest {
	msg := &accessrequestv1.AccessRequest{
		Id:                r.ID.String(),
		RequesterId:       r.RequesterID.String(),
		RoleId:            r.RoleID.String(),
		AssetId:           r.AssetID.String(),
		Status:            r.Status,
		RequiredApprovals: int32(r.RequiredApprovals), //nolint:gosec // bounded by policy
		ApprovalsSoFar:    int32(r.ApprovalsSoFar),    //nolint:gosec // small approval counts
		Reason:            r.Reason,
		CreatedAt:         r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !r.ResolvedAt.IsZero() {
		msg.ResolvedAt = r.ResolvedAt.UTC().Format(time.RFC3339)
	}
	if r.GrantID != uuid.Nil {
		msg.GrantId = r.GrantID.String()
	}
	return msg
}

func toGrantMsg(g accessrequest.Grant) *accessrequestv1.Grant {
	msg := &accessrequestv1.Grant{
		Id:            g.ID.String(),
		RoleId:        g.RoleID.String(),
		AssetId:       g.AssetID.String(),
		SubjectUserId: g.SubjectUserID.String(),
		GrantedAt:     g.GrantedAt.UTC().Format(time.RFC3339),
		ExpiresAt:     g.ExpiresAt.UTC().Format(time.RFC3339),
		RevokedReason: g.RevokedReason,
		Active:        g.Active,
	}
	if !g.RevokedAt.IsZero() {
		msg.RevokedAt = g.RevokedAt.UTC().Format(time.RFC3339)
	}
	return msg
}

// ResolveApproval returns the effective request policy for a (role, asset) pair (admin only).
func (s *AccessRequestServer) ResolveApproval(ctx context.Context, req *connect.Request[accessrequestv1.ResolveApprovalRequest]) (*connect.Response[accessrequestv1.ResolveApprovalResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "access:policy:read", authz.AssetScope(assetID)); err != nil {
		return nil, err
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
		RequiredApprovals: int32(rule.RequiredApprovals), //nolint:gosec // value is bounded 0-20 by proto validation
		ApproverRoleId:    approverRoleID,
	}), nil
}

// RequestAccess opens a JIT access request (authenticated).
func (s *AccessRequestServer) RequestAccess(ctx context.Context, req *connect.Request[accessrequestv1.RequestAccessRequest]) (*connect.Response[accessrequestv1.RequestAccessResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	dur := time.Duration(req.Msg.DurationSeconds) * time.Second
	out, err := s.svc.RequestAccess(ctx, caller.ID, roleID, assetID, dur, req.Msg.Reason)
	if err != nil {
		return nil, mapAccessRequestErr(err)
	}
	return connect.NewResponse(&accessrequestv1.RequestAccessResponse{Request: toAccessRequestMsg(out)}), nil
}

// CancelRequest cancels the caller's own pending request (authenticated).
func (s *AccessRequestServer) CancelRequest(ctx context.Context, req *connect.Request[accessrequestv1.CancelRequestRequest]) (*connect.Response[accessrequestv1.CancelRequestResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	requestID, err := uuid.Parse(req.Msg.RequestId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad request_id"))
	}
	if err := s.svc.Cancel(ctx, caller.ID, requestID); err != nil {
		return nil, mapAccessRequestErr(err)
	}
	return connect.NewResponse(&accessrequestv1.CancelRequestResponse{}), nil
}

// ApproveRequest records the caller's approval (authenticated).
func (s *AccessRequestServer) ApproveRequest(ctx context.Context, req *connect.Request[accessrequestv1.ApproveRequestRequest]) (*connect.Response[accessrequestv1.ApproveRequestResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	requestID, err := uuid.Parse(req.Msg.RequestId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad request_id"))
	}
	out, err := s.svc.Approve(ctx, caller.ID, requestID)
	if err != nil {
		return nil, mapAccessRequestErr(err)
	}
	return connect.NewResponse(&accessrequestv1.ApproveRequestResponse{Request: toAccessRequestMsg(out)}), nil
}

// DenyRequest records the caller's denial (authenticated).
func (s *AccessRequestServer) DenyRequest(ctx context.Context, req *connect.Request[accessrequestv1.DenyRequestRequest]) (*connect.Response[accessrequestv1.DenyRequestResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	requestID, err := uuid.Parse(req.Msg.RequestId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad request_id"))
	}
	out, err := s.svc.Deny(ctx, caller.ID, requestID)
	if err != nil {
		return nil, mapAccessRequestErr(err)
	}
	return connect.NewResponse(&accessrequestv1.DenyRequestResponse{Request: toAccessRequestMsg(out)}), nil
}

// ListMyRequests lists the caller's own requests (authenticated), ordered by
// (created_at DESC, id) with keyset pagination.
func (s *AccessRequestServer) ListMyRequests(ctx context.Context, req *connect.Request[accessrequestv1.ListMyRequestsRequest]) (*connect.Response[accessrequestv1.ListMyRequestsResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	page := accessrequest.PageParams{Limit: limit}
	if k != nil {
		page.AfterTs = k.Time
		page.AfterID = k.ID
	}
	rows, err := s.svc.ListMyRequestsPaged(ctx, caller.ID, page)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessrequestv1.ListMyRequestsResponse{}
	for i := range rows {
		out.Requests = append(out.Requests, toAccessRequestMsg(rows[i]))
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

// ListPendingApprovals lists pending requests the caller may approve (authenticated),
// ordered by (created_at DESC, id) with keyset pagination.
//
// Go-side IsApprover filtering happens after the SQL LIMIT, so a page may be
// shorter than page_size (or empty) when the pending set contains requests for
// policies the caller cannot approve. The next-page token is keyed to the SQL
// page position — not the filtered result — so pagination advances past
// filtered rows rather than stopping early.
func (s *AccessRequestServer) ListPendingApprovals(ctx context.Context, req *connect.Request[accessrequestv1.ListPendingApprovalsRequest]) (*connect.Response[accessrequestv1.ListPendingApprovalsResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	page := accessrequest.PageParams{Limit: limit}
	if k != nil {
		page.AfterTs = k.Time
		page.AfterID = k.ID
	}
	rows, next, err := s.svc.ListPendingApprovalsPaged(ctx, caller.ID, page)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessrequestv1.ListPendingApprovalsResponse{}
	for i := range rows {
		out.Requests = append(out.Requests, toAccessRequestMsg(rows[i]))
	}
	// Emit a token whenever the SQL page was full (next != nil), even if the
	// filtered result is short or empty. The cursor tracks the SQL position so
	// the next call resumes past everything already examined.
	if next != nil {
		out.NextPageToken = encodeTimeToken(next.Ts, next.ID)
	}
	return connect.NewResponse(out), nil
}

// RevokeGrant revokes an access grant (admin, subject self-revoke, or approver).
func (s *AccessRequestServer) RevokeGrant(ctx context.Context, req *connect.Request[accessrequestv1.RevokeGrantRequest]) (*connect.Response[accessrequestv1.RevokeGrantResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	grantID, err := uuid.Parse(req.Msg.GrantId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad grant_id"))
	}
	// Management revoke authority: holding the revoke cap globally lets a caller
	// revoke any grant (admins hold ** so this is a no-op for them). Without it the
	// service falls back to subject self-revoke / standing-approver authority.
	mgmtAuthorized := s.requireCap(ctx, "access:grant:revoke", authz.GlobalScope()) == nil
	g, err := s.svc.RevokeGrant(ctx, caller, mgmtAuthorized, grantID, req.Msg.Reason)
	if err != nil {
		return nil, mapAccessRequestErr(err)
	}
	out := toGrantMsg(s.svc.GrantDTO(g))
	return connect.NewResponse(&accessrequestv1.RevokeGrantResponse{Grant: out}), nil
}

// ListMyGrants lists the caller's own grants (authenticated), ordered by
// (granted_at DESC, id) with keyset pagination.
func (s *AccessRequestServer) ListMyGrants(ctx context.Context, req *connect.Request[accessrequestv1.ListMyGrantsRequest]) (*connect.Response[accessrequestv1.ListMyGrantsResponse], error) {
	caller, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	page := accessrequest.PageParams{Limit: limit}
	if k != nil {
		page.AfterTs = k.Time
		page.AfterID = k.ID
	}
	rows, err := s.svc.ListMyGrantsPaged(ctx, caller.ID, page)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessrequestv1.ListMyGrantsResponse{}
	for i := range rows {
		out.Grants = append(out.Grants, toGrantMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here granted_at (NOT created_at — access_grants has no created_at).
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.GrantedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// ListGrants lists grants for admin introspection (admin only), ordered by
// (granted_at DESC, id) with keyset pagination. The subject_user_id and
// active_only filters are preserved.
func (s *AccessRequestServer) ListGrants(ctx context.Context, req *connect.Request[accessrequestv1.ListGrantsRequest]) (*connect.Response[accessrequestv1.ListGrantsResponse], error) {
	if err := s.requireCap(ctx, "access:grant:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	filter := accessrequest.GrantFilter{ActiveOnly: req.Msg.ActiveOnly}
	if req.Msg.SubjectUserId != "" {
		sid, err := uuid.Parse(req.Msg.SubjectUserId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
		}
		filter.Subject = sid
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	page := accessrequest.PageParams{Limit: limit}
	if k != nil {
		page.AfterTs = k.Time
		page.AfterID = k.ID
	}
	rows, err := s.svc.ListGrantsPaged(ctx, filter, page)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessrequestv1.ListGrantsResponse{}
	for i := range rows {
		out.Grants = append(out.Grants, toGrantMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here granted_at (NOT created_at — access_grants has no created_at).
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.GrantedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}
