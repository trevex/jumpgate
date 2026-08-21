package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
)

type stubRoles struct {
	accessv1connect.UnimplementedAccessServiceHandler

	gotCreateRole  *accessv1.CreateRoleRequest
	gotResolveRole *accessv1.ResolveRoleRequest

	roles []*accessv1.Role
}

func (s *stubRoles) ResolveRole(_ context.Context, req *connect.Request[accessv1.ResolveRoleRequest]) (*connect.Response[accessv1.ResolveRoleResponse], error) {
	s.gotResolveRole = req.Msg
	return connect.NewResponse(&accessv1.ResolveRoleResponse{RoleId: "role-uuid-123", Path: req.Msg.GetRef()}), nil
}

func (s *stubRoles) CreateRole(_ context.Context, req *connect.Request[accessv1.CreateRoleRequest]) (*connect.Response[accessv1.CreateRoleResponse], error) {
	s.gotCreateRole = req.Msg
	return connect.NewResponse(&accessv1.CreateRoleResponse{Role: &accessv1.Role{
		Id:           "role-123",
		Name:         req.Msg.GetName(),
		Capabilities: req.Msg.GetCapabilities(),
	}}), nil
}

func (s *stubRoles) ListRoles(_ context.Context, _ *connect.Request[accessv1.ListRolesRequest]) (*connect.Response[accessv1.ListRolesResponse], error) {
	return connect.NewResponse(&accessv1.ListRolesResponse{Roles: s.roles}), nil
}

// resetRolesFlags restores mutated package-global flag state between runs so the
// repeatable --capability slice flag does not leak across tests.
func resetRolesFlags() {
	flagOutput = "table"
	rolesCreateCapabilities = nil
	rolesCreateFolder = ""
	rolesListCascade = false
	if f := rolesCreateCmd.Flags().Lookup("capability"); f != nil {
		_ = f.Value.(interface{ Replace([]string) error }).Replace(nil)
		f.Changed = false
	}
	if f := rolesCreateCmd.Flags().Lookup("folder"); f != nil {
		_ = f.Value.Set("")
		f.Changed = false
	}
	if f := rolesListCmd.Flags().Lookup("cascade"); f != nil {
		f.Changed = false
	}
}

func newRolesStub(t *testing.T, s *stubRoles) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRolesCreate(t *testing.T) {
	s := &stubRoles{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRolesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetRolesFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"roles", "create", "deployer",
		"--capability", "ssh:login:deploy",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateRole.GetName() != "deployer" {
		t.Fatalf("name=%q", s.gotCreateRole.GetName())
	}
	caps := s.gotCreateRole.GetCapabilities()
	if len(caps) != 1 || caps[0] != "ssh:login:deploy" {
		t.Fatalf("capabilities=%v", caps)
	}

	if !strings.Contains(out.String(), "role-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestRolesList(t *testing.T) {
	s := &stubRoles{roles: []*accessv1.Role{
		{Id: "role-1", Name: "deployer", Capabilities: []string{"ssh:login:deploy", "ssh:record:exempt"}},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRolesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetRolesFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"roles", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "role-1") || !strings.Contains(got, "deployer") {
		t.Fatalf("out=%s", got)
	}
	if !strings.Contains(got, "ssh:login:deploy") || !strings.Contains(got, "ssh:record:exempt") {
		t.Fatalf("capabilities missing from out=%s", got)
	}
}

// TestRolesCreateFolderUUID verifies that a --folder given as a uuid short-circuits
// (no ResolveFolder round-trip) and is forwarded as FolderId on CreateRole.
func TestRolesCreateFolderUUID(t *testing.T) {
	const folderID = "22222222-2222-2222-2222-222222222222"
	s := &stubRoles{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRolesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetRolesFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"roles", "create", "deployer",
		"--capability", "ssh:login:deploy",
		"--folder", folderID,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateRole.GetFolderId() != folderID {
		t.Fatalf("folder_id=%q, want %q", s.gotCreateRole.GetFolderId(), folderID)
	}
}

func TestRolesListParentCascade(t *testing.T) {
	s := &stubRoles{roles: []*accessv1.Role{
		{Id: "role-2", Name: "shell", FolderPath: "prod"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRolesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetRolesFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"roles", "list", "prod", "--cascade", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "role-2") || !strings.Contains(got, "shell") {
		t.Fatalf("out=%s", got)
	}
}

// TestResolveRoleIDViaRPC verifies resolveRoleID resolves a non-uuid ref via the
// ResolveRole RPC and returns the resolved role id.
func TestResolveRoleIDViaRPC(t *testing.T) {
	s := &stubRoles{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newRolesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetRolesFlags)

	cl, err := newClient()
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	id, err := resolveRoleID(context.Background(), cl, "engineer.db.prod")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if s.gotResolveRole.GetRef() != "engineer.db.prod" {
		t.Fatalf("ref=%q, want engineer.db.prod", s.gotResolveRole.GetRef())
	}
	if id != "role-uuid-123" {
		t.Fatalf("id=%q, want role-uuid-123", id)
	}
}
