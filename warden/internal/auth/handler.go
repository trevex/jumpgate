package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Handler implements authv1connect.AuthServiceHandler.
type Handler struct {
	q            *sqlc.Queries
	tokens       *TokenService
	authorizer   *authz.Authorizer
	throttle     *Throttle
	audit        *audit.Logger
	cookieSecure bool
	sessionTTL   time.Duration
}

// NewHandler constructs the AuthService implementation.
func NewHandler(q *sqlc.Queries, tokens *TokenService, authorizer *authz.Authorizer, throttle *Throttle, auditLog *audit.Logger, cookieSecure bool, sessionTTL time.Duration) *Handler {
	return &Handler{q: q, tokens: tokens, authorizer: authorizer, throttle: throttle, audit: auditLog, cookieSecure: cookieSecure, sessionTTL: sessionTTL}
}

// peerHost strips the port from a "host:port" peer address, falling back to
// the raw address if it isn't in that form.
func peerHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// jsonDetails marshals kv for an audit.Event's Details column, degrading to an
// empty object rather than failing the audit append on a marshal error.
func jsonDetails(kv map[string]string) []byte {
	b, err := json.Marshal(kv)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// recordAudit appends e best-effort: the RPC never fails on an audit error,
// but a broken chain for auth events must not fail silently.
func (s *Handler) recordAudit(ctx context.Context, e audit.Event) {
	if err := s.audit.Append(ctx, e); err != nil {
		slog.Error("audit append failed", "event", e.Type, "err", err)
	}
}

// Login exchanges email + password for a bearer token.
func (s *Handler) Login(ctx context.Context, req *connect.Request[authv1.LoginRequest]) (*connect.Response[authv1.LoginResponse], error) {
	unauth := connect.NewError(connect.CodeUnauthenticated, errors.New("invalid email or password"))
	email := NormalizeEmail(req.Msg.Email)
	// req.Peer().Addr is the direct client address; warden has no trusted proxy
	// today. ponytail: parse a trusted forwarded header once warden sits behind
	// an ingress that sets one.
	ip := peerHost(req.Peer().Addr)
	ua := req.Header().Get("User-Agent")

	if delay, blocked := s.throttle.Check(email, ip); blocked {
		s.recordAudit(ctx, audit.Event{Type: EventLoginThrottled, Details: jsonDetails(map[string]string{"ip": ip})})
		cerr := connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts; try again later"))
		secs := int(s.throttle.RetryAfter(email, ip).Seconds())
		if secs < 1 {
			secs = 1
		}
		cerr.Meta().Set("Retry-After", strconv.Itoa(secs))
		return nil, cerr
	} else if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		_, _ = VerifyPassword(req.Msg.Password, DummyHash) // constant-time: avoid user enumeration via timing
		s.throttle.Fail(email, ip)
		s.recordAudit(ctx, audit.Event{Type: EventLoginFailed, Details: jsonDetails(map[string]string{"reason": "unknown_user", "ip": ip})})
		return nil, unauth
	}
	ok, verr := VerifyPassword(req.Msg.Password, u.PasswordHash)
	// A deactivated account cannot acquire new credentials (deactivation is a
	// revocation trigger). Return the generic error to avoid disclosing state.
	if verr != nil || !ok || u.DeactivatedAt.Valid {
		s.throttle.Fail(email, ip)
		reason := "bad_password"
		if u.DeactivatedAt.Valid {
			reason = "deactivated"
		}
		s.recordAudit(ctx, audit.Event{Type: EventLoginFailed, ActorID: u.ID, Subject: "user:" + u.ID.String(), Details: jsonDetails(map[string]string{"reason": reason, "ip": ip})})
		return nil, unauth
	}

	s.throttle.Success(email, ip)
	label := "cli"
	if req.Msg.CookieOnly {
		label = "browser"
	}
	tok, err := s.tokens.Issue(ctx, u.ID, s.sessionTTL, TokenMeta{ClientIP: ip, UserAgent: ua, Label: label})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.recordAudit(ctx, audit.Event{Type: EventLoginSucceeded, ActorID: u.ID, Subject: "user:" + u.ID.String(), Details: jsonDetails(map[string]string{"ip": ip})})

	resp := connect.NewResponse(&authv1.LoginResponse{UserId: u.ID.String()})
	if req.Msg.CookieOnly {
		// Secure is config-gated: true in production, off only for the plaintext
		// dev/e2e env (which the browser would otherwise reject). HttpOnly and
		// SameSite=Strict are always set, so the cookie is not insecure by design.
		c := &http.Cookie{ //nolint:gosec // G124: HttpOnly + SameSite=Strict set; Secure is config-gated.
			Name:     SessionCookie,
			Value:    tok,
			Path:     "/",
			MaxAge:   int(s.sessionTTL / time.Second),
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
	u, ok := UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	raw, fromCookie := ExtractToken(req.Header())
	if raw != "" {
		_ = s.tokens.Revoke(ctx, raw) // idempotent: ignore already-revoked errors
	}
	s.recordAudit(ctx, audit.Event{Type: EventLogout, ActorID: u.ID, Subject: "user:" + u.ID.String(), Details: []byte("{}")})
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
