package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

const tokenTTL = 12 * time.Hour

// Handler implements authv1connect.AuthServiceHandler.
type Handler struct {
	q            *sqlc.Queries
	tokens       *TokenService
	authorizer   *authz.Authorizer
	cookieSecure bool
}

// NewHandler constructs the AuthService implementation.
func NewHandler(q *sqlc.Queries, tokens *TokenService, authorizer *authz.Authorizer, cookieSecure bool) *Handler {
	return &Handler{q: q, tokens: tokens, authorizer: authorizer, cookieSecure: cookieSecure}
}

// Login exchanges email + password for a bearer token.
func (s *Handler) Login(ctx context.Context, req *connect.Request[authv1.LoginRequest]) (*connect.Response[authv1.LoginResponse], error) {
	unauth := connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	u, err := s.q.GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		_, _ = VerifyPassword(req.Msg.Password, DummyHash) // constant-time: avoid user enumeration via timing
		return nil, unauth
	}
	ok, err := VerifyPassword(req.Msg.Password, u.PasswordHash)
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
	resp := connect.NewResponse(&authv1.LoginResponse{UserId: u.ID.String()})
	if req.Msg.CookieOnly {
		// Secure is config-gated: true in production, off only for the plaintext
		// dev/e2e env (which the browser would otherwise reject). HttpOnly and
		// SameSite=Strict are always set, so the cookie is not insecure by design.
		c := &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Strict set; Secure is config-gated.
			Name:     SessionCookie,
			Value:    tok,
			Path:     "/",
			MaxAge:   int(tokenTTL / time.Second),
			HttpOnly: true,
			Secure:   s.cookieSecure,
			SameSite: http.SameSiteStrictMode,
		}
		resp.Header().Set("Set-Cookie", c.String())
	} else {
		resp.Msg.Token = tok
	}
	return resp, nil
}

// Logout revokes the caller's current token and clears the session cookie.
func (s *Handler) Logout(ctx context.Context, req *connect.Request[authv1.LogoutRequest]) (*connect.Response[authv1.LogoutResponse], error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	raw, fromCookie := ExtractToken(req.Header())
	if raw != "" {
		_ = s.tokens.Revoke(ctx, raw) // idempotent: ignore already-revoked errors
	}
	resp := connect.NewResponse(&authv1.LogoutResponse{})
	if fromCookie {
		// Matches the login cookie's attributes so the browser replaces it; Secure
		// is config-gated (see Login). HttpOnly + SameSite=Strict are always set.
		c := &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Strict set; Secure is config-gated.
			Name:     SessionCookie,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   s.cookieSecure,
			SameSite: http.SameSiteStrictMode,
		}
		resp.Header().Set("Set-Cookie", c.String())
	}
	return resp, nil
}

// WhoAmI returns the caller's identity.
func (s *Handler) WhoAmI(ctx context.Context, _ *connect.Request[authv1.WhoAmIRequest]) (*connect.Response[authv1.WhoAmIResponse], error) {
	u, ok := UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	full, err := s.q.GetUserByID(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	caps, err := s.authorizer.CapabilitiesOnScope(ctx, u.ID, authz.GlobalScope())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&authv1.WhoAmIResponse{
		UserId:       full.ID.String(),
		Email:        full.Email,
		DisplayName:  full.DisplayName,
		Capabilities: []string(caps),
	}), nil
}
