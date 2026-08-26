package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

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
	g, err := s.q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: roleID, SourceRoleID: sourceRoleID, Via: req.Msg.Via})
	if err != nil {
		return nil, apierr.MapWrite(err)
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
	limit := apipage.ClampPageSize(req.Msg.PageSize)
	k, err := apipage.DecodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := sqlc.ListRoleGrantsParams{RoleID: roleID, Lim: limit}
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
		out.NextPageToken = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}
