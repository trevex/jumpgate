package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
)

type stubBindings struct {
	accessv1connect.UnimplementedAccessServiceHandler

	gotCreate *accessv1.CreateRoleBindingRequest
	gotList   *accessv1.ListRoleBindingsRequest
	gotDelete *accessv1.DeleteRoleBindingRequest

	bindings []*accessv1.RoleBinding
}

func (s *stubBindings) CreateRoleBinding(_ context.Context, req *connect.Request[accessv1.CreateRoleBindingRequest]) (*connect.Response[accessv1.CreateRoleBindingResponse], error) {
	s.gotCreate = req.Msg
	return connect.NewResponse(&accessv1.CreateRoleBindingResponse{Id: "binding-123"}), nil
}

func (s *stubBindings) ListRoleBindings(_ context.Context, req *connect.Request[accessv1.ListRoleBindingsRequest]) (*connect.Response[accessv1.ListRoleBindingsResponse], error) {
	s.gotList = req.Msg
	return connect.NewResponse(&accessv1.ListRoleBindingsResponse{Bindings: s.bindings}), nil
}

func (s *stubBindings) DeleteRoleBinding(_ context.Context, req *connect.Request[accessv1.DeleteRoleBindingRequest]) (*connect.Response[accessv1.DeleteRoleBindingResponse], error) {
	s.gotDelete = req.Msg
	return connect.NewResponse(&accessv1.DeleteRoleBindingResponse{}), nil
}

func newBindingsStub(t *testing.T, s *stubBindings) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// resetBindingsFlags restores mutated package-global flag state between runs so
// the string flags do not leak across tests.
func resetBindingsFlags() {
	flagOutput = "table"
	bindingsCreateRole = ""
	bindingsCreateUser = ""
	bindingsCreateGroup = ""
	bindingsCreateAsset = ""
	bindingsCreateFolder = ""
	bindingsListUser = ""
	bindingsListAsset = ""
	for _, spec := range []struct {
		cmd  *cobra.Command
		name string
	}{
		{bindingsCreateCmd, "role"},
		{bindingsCreateCmd, "user"},
		{bindingsCreateCmd, "group"},
		{bindingsCreateCmd, "asset"},
		{bindingsCreateCmd, "folder"},
		{bindingsListCmd, "user"},
		{bindingsListCmd, "asset"},
	} {
		if f := spec.cmd.Flags().Lookup(spec.name); f != nil {
			_ = f.Value.Set("")
			f.Changed = false
		}
	}
}

func TestBindingsCreate(t *testing.T) {
	s := &stubBindings{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newBindingsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetBindingsFlags)

	// Pass UUIDs directly so resolution is a passthrough and no Identity/Catalog
	// stub is needed.
	const (
		roleID  = "11111111-1111-1111-1111-111111111111"
		userID  = "22222222-2222-2222-2222-222222222222"
		assetID = "33333333-3333-3333-3333-333333333333"
	)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"bindings", "create",
		"--role", roleID,
		"--user", userID,
		"--asset", assetID,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreate == nil {
		t.Fatalf("CreateRoleBinding not called")
	}
	if s.gotCreate.GetRoleId() != roleID {
		t.Fatalf("role_id=%q", s.gotCreate.GetRoleId())
	}
	if s.gotCreate.GetSubjectUserId() != userID {
		t.Fatalf("subject_user_id=%q", s.gotCreate.GetSubjectUserId())
	}
	if s.gotCreate.GetSubjectGroupId() != "" {
		t.Fatalf("subject_group_id should be empty, got %q", s.gotCreate.GetSubjectGroupId())
	}
	if s.gotCreate.GetScopeAssetId() != assetID {
		t.Fatalf("scope_asset_id=%q", s.gotCreate.GetScopeAssetId())
	}
	if s.gotCreate.GetScopeFolderId() != "" {
		t.Fatalf("scope_folder_id should be empty, got %q", s.gotCreate.GetScopeFolderId())
	}
	if !strings.Contains(out.String(), "binding-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestBindingsCreateRejectsTwoSubjects(t *testing.T) {
	s := &stubBindings{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newBindingsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetBindingsFlags)

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"bindings", "create",
		"--role", "11111111-1111-1111-1111-111111111111",
		"--user", "22222222-2222-2222-2222-222222222222",
		"--group", "44444444-4444-4444-4444-444444444444",
		"--asset", "33333333-3333-3333-3333-333333333333",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error for two subject flags")
	}
	if s.gotCreate != nil {
		t.Fatalf("CreateRoleBinding should not have been called")
	}
}

func TestBindingsDelete(t *testing.T) {
	s := &stubBindings{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newBindingsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetBindingsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"bindings", "delete", "binding-xyz"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if s.gotDelete == nil || s.gotDelete.GetId() != "binding-xyz" {
		t.Fatalf("delete req=%+v", s.gotDelete)
	}
}

func TestBindingsList(t *testing.T) {
	s := &stubBindings{bindings: []*accessv1.RoleBinding{
		{Id: "b-1", RoleId: "r-1", SubjectUserId: "u-1", ScopeAssetId: "a-1"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newBindingsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetBindingsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"bindings", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "b-1") || !strings.Contains(got, "r-1") {
		t.Fatalf("out=%s", got)
	}
}
