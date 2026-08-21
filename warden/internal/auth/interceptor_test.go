package auth_test

// Interceptor tests drive the interceptor through a real in-memory connect
// handler (httptest.NewServer + generated AuthService) so that
// req.Spec().IsClient is correctly set to false (server branch) and
// req.Header() is backed by real HTTP headers. A fake userLookup accepts a
// single known token. The stub WhoAmI handler captures the attached user from
// the request context and returns it; the test inspects it via the response.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/auth"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
)

// ── fake lookup ───────────────────────────────────────────────────────────────

const fakeToken = "validtoken"

var fakeUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

type fakeLookup struct{}

func (fakeLookup) Validate(_ context.Context, raw string) (uuid.UUID, error) {
	if raw == fakeToken {
		return fakeUserID, nil
	}
	return uuid.Nil, errors.New("invalid")
}

func (fakeLookup) Load(_ context.Context, id uuid.UUID) (auth.CurrentUser, error) {
	if id == fakeUserID {
		return auth.CurrentUser{ID: fakeUserID, Email: "alice@example.com"}, nil
	}
	return auth.CurrentUser{}, errors.New("not found")
}

// ── stub service ──────────────────────────────────────────────────────────────

// stubAuthService implements authv1connect.AuthServiceHandler.
// WhoAmI reports the email of the attached user (or "none" if unauthenticated).
type stubAuthService struct{}

func (stubAuthService) Login(
	_ context.Context,
	_ *connect.Request[authv1.LoginRequest],
) (*connect.Response[authv1.LoginResponse], error) {
	return connect.NewResponse(&authv1.LoginResponse{}), nil
}

func (stubAuthService) WhoAmI(
	ctx context.Context,
	_ *connect.Request[authv1.WhoAmIRequest],
) (*connect.Response[authv1.WhoAmIResponse], error) {
	email := "none"
	if u, ok := auth.UserFromContext(ctx); ok {
		email = u.Email
	}
	return connect.NewResponse(&authv1.WhoAmIResponse{Email: email}), nil
}

// ── test harness ──────────────────────────────────────────────────────────────

// newTestServer spins up a real httptest server with the auth interceptor wired
// in. It returns the server URL (closed automatically via t.Cleanup).
func newTestServer(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	interceptor := auth.NewInterceptor(fakeLookup{})
	path, handler := authv1connect.NewAuthServiceHandler(
		stubAuthService{},
		connect.WithInterceptors(interceptor),
	)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// whoAmI invokes WhoAmI with the provided headers applied to the request and
// returns the email field. Extra headers are set as k/v pairs.
func whoAmI(t *testing.T, serverURL string, headers map[string]string) string {
	t.Helper()
	client := authv1connect.NewAuthServiceClient(http.DefaultClient, serverURL)
	req := connect.NewRequest(&authv1.WhoAmIRequest{})
	for k, v := range headers {
		req.Header().Set(k, v)
	}
	resp, err := client.WhoAmI(context.Background(), req)
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	return resp.Msg.GetEmail()
}

// ── cases ─────────────────────────────────────────────────────────────────────

func TestInterceptor(t *testing.T) {
	serverURL := newTestServer(t)

	tests := []struct {
		name       string
		headers    map[string]string
		wantAttach bool // true  → email=="alice@example.com", false → "none"
	}{
		{
			name:       "bearer good → attach",
			headers:    map[string]string{"Authorization": "Bearer " + fakeToken},
			wantAttach: true,
		},
		{
			name:       "bearer bad → no attach",
			headers:    map[string]string{"Authorization": "Bearer wrongtoken"},
			wantAttach: false,
		},
		{
			name: "cookie + same-origin → attach",
			headers: map[string]string{
				"Cookie":         auth.SessionCookie + "=" + fakeToken,
				"Sec-Fetch-Site": "same-origin",
			},
			wantAttach: true,
		},
		{
			name: "cookie + cross-site → NO attach (CSRF blocked)",
			headers: map[string]string{
				"Cookie":         auth.SessionCookie + "=" + fakeToken,
				"Sec-Fetch-Site": "cross-site",
			},
			wantAttach: false,
		},
		{
			name: "cookie + no Sec-Fetch-Site → NO attach (fail closed)",
			headers: map[string]string{
				"Cookie": auth.SessionCookie + "=" + fakeToken,
			},
			wantAttach: false,
		},
		{
			name: "bearer + cross-site → attach (CLI unaffected by CSRF gate)",
			headers: map[string]string{
				"Authorization":  "Bearer " + fakeToken,
				"Sec-Fetch-Site": "cross-site",
			},
			wantAttach: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := whoAmI(t, serverURL, tc.headers)
			if tc.wantAttach {
				if got != "alice@example.com" {
					t.Errorf("expected user attached (alice@example.com), got %q", got)
				}
			} else {
				if got != "none" {
					t.Errorf("expected no user attached, got %q", got)
				}
			}
		})
	}
}

func TestContextUserRoundTrip(t *testing.T) {
	u := auth.CurrentUser{ID: uuid.New(), Email: "a@x"}
	ctx := auth.WithUser(context.Background(), u)

	got, ok := auth.UserFromContext(ctx)
	if !ok {
		t.Fatal("no user in context")
	}
	if got.ID != u.ID || got.Email != u.Email {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	if _, ok := auth.UserFromContext(context.Background()); ok {
		t.Fatal("empty context should have no user")
	}
}
