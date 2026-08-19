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

type stubPolicies struct {
	accessv1connect.UnimplementedAccessServiceHandler

	gotCreate     *accessv1.CreateRequestPolicyRequest
	gotList       *accessv1.ListRequestPoliciesRequest
	gotAddSubject *accessv1.AddPolicySubjectRequest

	policies []*accessv1.RequestPolicy
}

func (s *stubPolicies) CreateRequestPolicy(_ context.Context, req *connect.Request[accessv1.CreateRequestPolicyRequest]) (*connect.Response[accessv1.CreateRequestPolicyResponse], error) {
	s.gotCreate = req.Msg
	return connect.NewResponse(&accessv1.CreateRequestPolicyResponse{
		Policy: &accessv1.RequestPolicy{
			Id:                "policy-123",
			RoleId:            req.Msg.GetRoleId(),
			ScopeAssetId:      req.Msg.GetScopeAssetId(),
			ScopeFolderId:     req.Msg.GetScopeFolderId(),
			RequiredApprovals: req.Msg.GetRequiredApprovals(),
			RequesterRoleId:   req.Msg.GetRequesterRoleId(),
			ApproverRoleId:    req.Msg.GetApproverRoleId(),
		},
	}), nil
}

func (s *stubPolicies) ListRequestPolicies(_ context.Context, req *connect.Request[accessv1.ListRequestPoliciesRequest]) (*connect.Response[accessv1.ListRequestPoliciesResponse], error) {
	s.gotList = req.Msg
	return connect.NewResponse(&accessv1.ListRequestPoliciesResponse{Policies: s.policies}), nil
}

func (s *stubPolicies) AddPolicySubject(_ context.Context, req *connect.Request[accessv1.AddPolicySubjectRequest]) (*connect.Response[accessv1.AddPolicySubjectResponse], error) {
	s.gotAddSubject = req.Msg
	return connect.NewResponse(&accessv1.AddPolicySubjectResponse{Id: "subject-456"}), nil
}

func newPoliciesStub(t *testing.T, s *stubPolicies) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// resetPoliciesFlags restores mutated package-global flag state between runs so
// the string/int flags do not leak across tests.
func resetPoliciesFlags() {
	flagOutput = "table"
	policiesCreateRequestRole = ""
	policiesCreateAsset = ""
	policiesCreateFolder = ""
	policiesCreateApproverRole = ""
	policiesCreateRequesterRole = ""
	policiesCreateMinApprovals = 0
	policiesAddSubjectKind = ""
	policiesAddSubjectUser = ""
	policiesAddSubjectGroup = ""
	for _, spec := range []struct {
		cmd  *cobra.Command
		name string
	}{
		{policiesCreateCmd, "request-role"},
		{policiesCreateCmd, "asset"},
		{policiesCreateCmd, "folder"},
		{policiesCreateCmd, "approver-role"},
		{policiesCreateCmd, "requester-role"},
		{policiesCreateCmd, "min-approvals"},
		{policiesAddSubjectCmd, "kind"},
		{policiesAddSubjectCmd, "user"},
		{policiesAddSubjectCmd, "group"},
	} {
		if f := spec.cmd.Flags().Lookup(spec.name); f != nil {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
}

func TestPoliciesCreate(t *testing.T) {
	s := &stubPolicies{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newPoliciesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetPoliciesFlags)

	// Pass UUIDs directly so resolution is a passthrough and no Identity/Catalog
	// stub is needed.
	const (
		requestRoleID  = "11111111-1111-1111-1111-111111111111"
		approverRoleID = "22222222-2222-2222-2222-222222222222"
		assetID        = "33333333-3333-3333-3333-333333333333"
	)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"policies", "create",
		"--request-role", requestRoleID,
		"--asset", assetID,
		"--approver-role", approverRoleID,
		"--min-approvals", "2",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreate == nil {
		t.Fatalf("CreateRequestPolicy not called")
	}
	if s.gotCreate.GetRoleId() != requestRoleID {
		t.Fatalf("role_id=%q", s.gotCreate.GetRoleId())
	}
	if s.gotCreate.GetScopeAssetId() != assetID {
		t.Fatalf("scope_asset_id=%q", s.gotCreate.GetScopeAssetId())
	}
	if s.gotCreate.GetScopeFolderId() != "" {
		t.Fatalf("scope_folder_id should be empty, got %q", s.gotCreate.GetScopeFolderId())
	}
	if s.gotCreate.GetApproverRoleId() != approverRoleID {
		t.Fatalf("approver_role_id=%q", s.gotCreate.GetApproverRoleId())
	}
	if s.gotCreate.GetRequiredApprovals() != 2 {
		t.Fatalf("required_approvals=%d", s.gotCreate.GetRequiredApprovals())
	}
	if !strings.Contains(out.String(), "policy-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestPoliciesCreateRejectsTwoScopes(t *testing.T) {
	s := &stubPolicies{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newPoliciesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetPoliciesFlags)

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"policies", "create",
		"--request-role", "11111111-1111-1111-1111-111111111111",
		"--asset", "33333333-3333-3333-3333-333333333333",
		"--folder", "44444444-4444-4444-4444-444444444444",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected error for two scope flags")
	}
	if s.gotCreate != nil {
		t.Fatalf("CreateRequestPolicy should not have been called")
	}
}

func TestPoliciesAddSubject(t *testing.T) {
	s := &stubPolicies{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newPoliciesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetPoliciesFlags)

	const userID = "22222222-2222-2222-2222-222222222222"

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"policies", "add-subject", "policy-xyz",
		"--kind", "approver",
		"--user", userID,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotAddSubject == nil {
		t.Fatalf("AddPolicySubject not called")
	}
	if s.gotAddSubject.GetPolicyId() != "policy-xyz" {
		t.Fatalf("policy_id=%q", s.gotAddSubject.GetPolicyId())
	}
	if s.gotAddSubject.GetKind() != "approver" {
		t.Fatalf("kind=%q", s.gotAddSubject.GetKind())
	}
	if s.gotAddSubject.GetSubjectUserId() != userID {
		t.Fatalf("subject_user_id=%q", s.gotAddSubject.GetSubjectUserId())
	}
	if s.gotAddSubject.GetSubjectGroupId() != "" {
		t.Fatalf("subject_group_id should be empty, got %q", s.gotAddSubject.GetSubjectGroupId())
	}
	if !strings.Contains(out.String(), "subject-456") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestPoliciesAddSubjectRejectsTwoSubjects(t *testing.T) {
	s := &stubPolicies{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newPoliciesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetPoliciesFlags)

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"policies", "add-subject", "policy-xyz",
		"--kind", "approver",
		"--user", "22222222-2222-2222-2222-222222222222",
		"--group", "44444444-4444-4444-4444-444444444444",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected error for two subject flags")
	}
	if s.gotAddSubject != nil {
		t.Fatalf("AddPolicySubject should not have been called")
	}
}

func TestPoliciesList(t *testing.T) {
	s := &stubPolicies{policies: []*accessv1.RequestPolicy{
		{Id: "p-1", RoleId: "r-1", ScopeAssetId: "a-1", RequiredApprovals: 1, ApproverRoleId: "ar-1"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newPoliciesStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetPoliciesFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"policies", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "p-1") || !strings.Contains(got, "r-1") {
		t.Fatalf("out=%s", got)
	}
}
