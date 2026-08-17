package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// IdentityServer implements identityv1connect.IdentityServiceHandler.
type IdentityServer struct {
	q      *gen.Queries
	tokens *auth.TokenService
}

// NewIdentityServer constructs the IdentityService implementation.
func NewIdentityServer(q *gen.Queries, tokens *auth.TokenService) *IdentityServer {
	return &IdentityServer{q: q, tokens: tokens}
}

func toUserMsg(u gen.User) *identityv1.User {
	return &identityv1.User{Id: u.ID.String(), Email: u.Email, DisplayName: u.DisplayName, IsAdmin: u.IsAdmin}
}

func toGroupMsg(g gen.Group) *identityv1.Group {
	return &identityv1.Group{Id: g.ID.String(), Name: g.Name}
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// CreateUser creates a local user (admin only).
func (s *IdentityServer) CreateUser(ctx context.Context, req *connect.Request[identityv1.CreateUserRequest]) (*connect.Response[identityv1.CreateUserResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	u, err := s.q.CreateUserFull(ctx, gen.CreateUserFullParams{
		Email: req.Msg.Email, DisplayName: req.Msg.DisplayName, IsAdmin: req.Msg.IsAdmin,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("email already exists"))
	}
	if err := s.q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.CreateUserResponse{User: toUserMsg(u)}), nil
}

// GetUser returns a user by ID (admin only). Unknown IDs return NotFound.
func (s *IdentityServer) GetUser(ctx context.Context, req *connect.Request[identityv1.GetUserRequest]) (*connect.Response[identityv1.GetUserResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return connect.NewResponse(&identityv1.GetUserResponse{User: toUserMsg(u)}), nil
}

// ListUsers returns a page of users (admin only), ordered by id.
func (s *IdentityServer) ListUsers(ctx context.Context, req *connect.Request[identityv1.ListUsersRequest]) (*connect.Response[identityv1.ListUsersResponse], error) {
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
	rows, err := s.q.ListUsers(ctx, gen.ListUsersParams{Column1: after, Limit: limit})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &identityv1.ListUsersResponse{}
	for i := range rows {
		out.Users = append(out.Users, toUserMsg(rows[i]))
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// CreateGroup creates a group (admin only).
func (s *IdentityServer) CreateGroup(ctx context.Context, req *connect.Request[identityv1.CreateGroupRequest]) (*connect.Response[identityv1.CreateGroupResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	g, err := s.q.CreateGroup(ctx, req.Msg.Name)
	if err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("group name already exists"))
	}
	return connect.NewResponse(&identityv1.CreateGroupResponse{Group: toGroupMsg(g)}), nil
}

// ListGroups returns a page of groups (admin only), ordered by id.
func (s *IdentityServer) ListGroups(ctx context.Context, req *connect.Request[identityv1.ListGroupsRequest]) (*connect.Response[identityv1.ListGroupsResponse], error) {
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
	rows, err := s.q.ListGroupsPaged(ctx, gen.ListGroupsPagedParams{Column1: after, Limit: limit})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &identityv1.ListGroupsResponse{}
	for i := range rows {
		out.Groups = append(out.Groups, toGroupMsg(rows[i]))
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// AddUserToGroup adds a user as a member of a group (admin only).
func (s *IdentityServer) AddUserToGroup(ctx context.Context, req *connect.Request[identityv1.AddUserToGroupRequest]) (*connect.Response[identityv1.AddUserToGroupResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: gid, MemberUserID: pgUUID(uid)}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.AddUserToGroupResponse{}), nil
}

// AddGroupToGroup nests one group inside another (admin only).
func (s *IdentityServer) AddGroupToGroup(ctx context.Context, req *connect.Request[identityv1.AddGroupToGroupRequest]) (*connect.Response[identityv1.AddGroupToGroupResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	mid, err := uuid.Parse(req.Msg.MemberGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad member_group_id"))
	}
	if err := s.q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: gid, MemberGroupID: pgUUID(mid)}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.AddGroupToGroupResponse{}), nil
}
