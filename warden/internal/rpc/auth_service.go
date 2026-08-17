package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// AuthServer implements authv1connect.AuthServiceHandler.
type AuthServer struct {
	q      *gen.Queries
	tokens *auth.TokenService
}

// NewAuthServer constructs the AuthService implementation.
func NewAuthServer(q *gen.Queries, tokens *auth.TokenService) *AuthServer {
	return &AuthServer{q: q, tokens: tokens}
}

// Login exchanges email + password for a bearer token. Stub — implemented in Task 8.
func (s *AuthServer) Login(_ context.Context, _ *connect.Request[authv1.LoginRequest]) (*connect.Response[authv1.LoginResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// WhoAmI returns the caller's identity. Stub — implemented in Task 8.
func (s *AuthServer) WhoAmI(_ context.Context, _ *connect.Request[authv1.WhoAmIRequest]) (*connect.Response[authv1.WhoAmIResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
