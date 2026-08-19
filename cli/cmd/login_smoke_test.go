package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"github.com/trevex/jumpgate/cli/internal/config"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
)

type stubAuth struct {
	authv1connect.UnimplementedAuthServiceHandler
}

func (stubAuth) Login(_ context.Context, req *connect.Request[authv1.LoginRequest]) (*connect.Response[authv1.LoginResponse], error) {
	if req.Msg.Email == "good@x" && req.Msg.Password == "pw" {
		return connect.NewResponse(&authv1.LoginResponse{Token: "tok-123", IsAdmin: true}), nil
	}
	return nil, connect.NewError(connect.CodeUnauthenticated, nil)
}

func newStub(t *testing.T) string {
	mux := http.NewServeMux()
	path, h := authv1connect.NewAuthServiceHandler(stubAuth{})
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestLoginSuccessStoresToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	flagCfg = config.Config{WardenAddr: newStub(t)}
	loginEmail, loginPassword = "good@x", "pw"
	loginCmd.SetContext(context.Background())
	loginCmd.SetOut(&bytes.Buffer{})
	if err := runLogin(loginCmd, nil); err != nil {
		t.Fatalf("login: %v", err)
	}
	c, _ := config.Load()
	if c.Token != "tok-123" {
		t.Fatalf("token not stored: %q", c.Token)
	}
}

func TestLoginBadCredsCleanError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	flagCfg = config.Config{WardenAddr: newStub(t)}
	loginEmail, loginPassword = "bad@x", "nope"
	loginCmd.SetContext(context.Background())
	err := runLogin(loginCmd, nil)
	if err == nil || err.Error() != "login failed: invalid email or password" {
		t.Fatalf("expected clean unauth error, got %v", err)
	}
}
