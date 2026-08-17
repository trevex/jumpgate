package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

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

// CreateUser creates a new user. Stub — implemented in Task 9.
func (s *IdentityServer) CreateUser(_ context.Context, _ *connect.Request[identityv1.CreateUserRequest]) (*connect.Response[identityv1.CreateUserResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// GetUser retrieves a user by ID. Stub — implemented in Task 9.
func (s *IdentityServer) GetUser(_ context.Context, _ *connect.Request[identityv1.GetUserRequest]) (*connect.Response[identityv1.GetUserResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// ListUsers returns a paginated list of users. Stub — implemented in Task 9.
func (s *IdentityServer) ListUsers(_ context.Context, _ *connect.Request[identityv1.ListUsersRequest]) (*connect.Response[identityv1.ListUsersResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// CreateGroup creates a new group. Stub — implemented in Task 10.
func (s *IdentityServer) CreateGroup(_ context.Context, _ *connect.Request[identityv1.CreateGroupRequest]) (*connect.Response[identityv1.CreateGroupResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// ListGroups returns a paginated list of groups. Stub — implemented in Task 10.
func (s *IdentityServer) ListGroups(_ context.Context, _ *connect.Request[identityv1.ListGroupsRequest]) (*connect.Response[identityv1.ListGroupsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// AddUserToGroup adds a user to a group. Stub — implemented in Task 10.
func (s *IdentityServer) AddUserToGroup(_ context.Context, _ *connect.Request[identityv1.AddUserToGroupRequest]) (*connect.Response[identityv1.AddUserToGroupResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// AddGroupToGroup adds a group as a member of another group. Stub — implemented in Task 10.
func (s *IdentityServer) AddGroupToGroup(_ context.Context, _ *connect.Request[identityv1.AddGroupToGroupRequest]) (*connect.Response[identityv1.AddGroupToGroupResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
