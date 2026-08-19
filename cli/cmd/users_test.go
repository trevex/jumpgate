package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

type stubIdentity struct {
	identityv1connect.UnimplementedIdentityServiceHandler
	gotCreate *identityv1.CreateUserRequest
}

func (s *stubIdentity) CreateUser(_ context.Context, req *connect.Request[identityv1.CreateUserRequest]) (*connect.Response[identityv1.CreateUserResponse], error) {
	s.gotCreate = req.Msg
	return connect.NewResponse(&identityv1.CreateUserResponse{User: &identityv1.User{
		Id:          "u1",
		Email:       req.Msg.GetEmail(),
		DisplayName: req.Msg.GetDisplayName(),
		IsAdmin:     req.Msg.GetIsAdmin(),
	}}), nil
}

func (s *stubIdentity) ListUsers(_ context.Context, _ *connect.Request[identityv1.ListUsersRequest]) (*connect.Response[identityv1.ListUsersResponse], error) {
	return connect.NewResponse(&identityv1.ListUsersResponse{Users: []*identityv1.User{
		{Id: "u1", Email: "a@x", DisplayName: "Alice", IsAdmin: true},
	}}), nil
}

// newIdentityStub starts an httptest server serving the given identity handler
// and returns its base URL.
func newIdentityStub(t *testing.T, h identityv1connect.IdentityServiceHandler) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(identityv1connect.NewIdentityServiceHandler(h))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestUsersCreate(t *testing.T) {
	s := &stubIdentity{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"users", "create", "alice@x", "--name", "Alice", "--admin", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreate.GetEmail() != "alice@x" || s.gotCreate.GetDisplayName() != "Alice" || !s.gotCreate.GetIsAdmin() {
		t.Fatalf("req=%+v", s.gotCreate)
	}
	if !strings.Contains(out.String(), "u1") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestUsersCreatePassword(t *testing.T) {
	s := &stubIdentity{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"users", "create", "alice@x", "--password", "s3cret-pw", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := s.gotCreate.GetPassword(); got != "s3cret-pw" {
		t.Fatalf("password not forwarded: got %q", got)
	}
}

func TestUsersList(t *testing.T) {
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, &stubIdentity{}))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"users", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "u1") || !strings.Contains(got, "a@x") {
		t.Fatalf("out=%s", got)
	}
}

func TestUsersCreateNotLoggedIn(t *testing.T) {
	// Isolate the config dir so the test reads no stored context — otherwise a real
	// ~/.config/jumpgate login would supply a token and defeat the not-logged-in check.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", "http://127.0.0.1:0")
	t.Setenv("JUMPGATE_TOKEN", "")
	t.Cleanup(func() { flagOutput = "table" })

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"users", "create", "alice@x", "--name", "Alice", "-o", "json"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Fatalf("expected not-logged-in error, got %v", err)
	}
}
