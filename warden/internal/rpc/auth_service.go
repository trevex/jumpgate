package rpc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

const tokenTTL = 12 * time.Hour

// AuthServer implements authv1connect.AuthServiceHandler.
type AuthServer struct {
	q      *gen.Queries
	tokens *auth.TokenService
}

// NewAuthServer constructs the AuthService implementation.
func NewAuthServer(q *gen.Queries, tokens *auth.TokenService) *AuthServer {
	return &AuthServer{q: q, tokens: tokens}
}

// Login exchanges email + password for a bearer token.
func (s *AuthServer) Login(ctx context.Context, req *connect.Request[authv1.LoginRequest]) (*connect.Response[authv1.LoginResponse], error) {
	unauth := connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	u, err := s.q.GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		_, _ = auth.VerifyPassword(req.Msg.Password, auth.DummyHash) // constant-time: avoid user enumeration via timing
		return nil, unauth
	}
	ok, err := auth.VerifyPassword(req.Msg.Password, u.PasswordHash)
	if err != nil || !ok {
		return nil, unauth
	}
	// A deactivated account cannot acquire new credentials (deactivation is a
	// revocation trigger). Return the generic error to avoid disclosing state.
	if u.DeactivatedAt.Valid {
		return nil, unauth
	}
	tok, err := s.tokens.Issue(ctx, u.ID, tokenTTL)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&authv1.LoginResponse{Token: tok, UserId: u.ID.String(), IsAdmin: u.IsAdmin}), nil
}

// WhoAmI returns the caller's identity.
func (s *AuthServer) WhoAmI(ctx context.Context, _ *connect.Request[authv1.WhoAmIRequest]) (*connect.Response[authv1.WhoAmIResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	full, err := s.q.GetUserByID(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&authv1.WhoAmIResponse{UserId: full.ID.String(), Email: full.Email, DisplayName: full.DisplayName, IsAdmin: full.IsAdmin}), nil
}
