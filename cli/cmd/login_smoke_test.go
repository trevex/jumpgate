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
	flagWardenAddr = newStub(t)
	t.Cleanup(func() { flagWardenAddr = "" })
	loginEmail, loginPassword = "good@x", "pw"
	loginCmd.SetContext(context.Background())
	loginCmd.SetOut(&bytes.Buffer{})
	if err := runLogin(loginCmd, nil); err != nil {
		t.Fatalf("login: %v", err)
	}
	f, _ := config.LoadFile()
	if f.Contexts["default"].Token != "tok-123" {
		t.Fatalf("token not stored: %q", f.Contexts["default"].Token)
	}
}

func TestLoginContextSelectsNamedContext(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	flagWardenAddr = newStub(t)
	t.Cleanup(func() { flagWardenAddr = "" })
	loginEmail, loginPassword = "good@x", "pw"
	t.Cleanup(func() { loginContext = "default" })
	loginContext = "bob"
	loginCmd.SetContext(context.Background())
	loginCmd.SetOut(&bytes.Buffer{})
	if err := runLogin(loginCmd, nil); err != nil {
		t.Fatalf("login: %v", err)
	}
	f, _ := config.LoadFile()
	if f.CurrentContext != "bob" {
		t.Fatalf("current=%q", f.CurrentContext)
	}
	if f.Contexts["bob"].Token != "tok-123" {
		t.Fatalf("token not stored under bob: %q", f.Contexts["bob"].Token)
	}
}

func TestLoginBadCredsCleanError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	flagWardenAddr = newStub(t)
	t.Cleanup(func() { flagWardenAddr = "" })
	loginEmail, loginPassword = "bad@x", "nope"
	loginCmd.SetContext(context.Background())
	err := runLogin(loginCmd, nil)
	if err == nil || err.Error() != "login failed: invalid email or password" {
		t.Fatalf("expected clean unauth error, got %v", err)
	}
}
