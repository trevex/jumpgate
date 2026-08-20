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

	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
)

type stubAccessRequest struct {
	accessrequestv1connect.UnimplementedAccessRequestServiceHandler

	gotRequest *accessrequestv1.RequestAccessRequest
	gotApprove *accessrequestv1.ApproveRequestRequest
	gotDeny    *accessrequestv1.DenyRequestRequest

	calledListMyRequests      bool
	calledListPendingApproval bool
	calledListMyGrants        bool

	requests []*accessrequestv1.AccessRequest
	grants   []*accessrequestv1.Grant
}

func (s *stubAccessRequest) RequestAccess(_ context.Context, req *connect.Request[accessrequestv1.RequestAccessRequest]) (*connect.Response[accessrequestv1.RequestAccessResponse], error) {
	s.gotRequest = req.Msg
	return connect.NewResponse(&accessrequestv1.RequestAccessResponse{
		Request: &accessrequestv1.AccessRequest{Id: "req-123", Status: "pending"},
	}), nil
}

func (s *stubAccessRequest) ApproveRequest(_ context.Context, req *connect.Request[accessrequestv1.ApproveRequestRequest]) (*connect.Response[accessrequestv1.ApproveRequestResponse], error) {
	s.gotApprove = req.Msg
	return connect.NewResponse(&accessrequestv1.ApproveRequestResponse{
		Request: &accessrequestv1.AccessRequest{Id: req.Msg.GetRequestId(), Status: "granted"},
	}), nil
}

func (s *stubAccessRequest) DenyRequest(_ context.Context, req *connect.Request[accessrequestv1.DenyRequestRequest]) (*connect.Response[accessrequestv1.DenyRequestResponse], error) {
	s.gotDeny = req.Msg
	return connect.NewResponse(&accessrequestv1.DenyRequestResponse{
		Request: &accessrequestv1.AccessRequest{Id: req.Msg.GetRequestId(), Status: "denied"},
	}), nil
}

func (s *stubAccessRequest) ListMyRequests(_ context.Context, _ *connect.Request[accessrequestv1.ListMyRequestsRequest]) (*connect.Response[accessrequestv1.ListMyRequestsResponse], error) {
	s.calledListMyRequests = true
	return connect.NewResponse(&accessrequestv1.ListMyRequestsResponse{Requests: s.requests}), nil
}

func (s *stubAccessRequest) ListPendingApprovals(_ context.Context, _ *connect.Request[accessrequestv1.ListPendingApprovalsRequest]) (*connect.Response[accessrequestv1.ListPendingApprovalsResponse], error) {
	s.calledListPendingApproval = true
	return connect.NewResponse(&accessrequestv1.ListPendingApprovalsResponse{Requests: s.requests}), nil
}

func (s *stubAccessRequest) ListMyGrants(_ context.Context, _ *connect.Request[accessrequestv1.ListMyGrantsRequest]) (*connect.Response[accessrequestv1.ListMyGrantsResponse], error) {
	s.calledListMyGrants = true
	return connect.NewResponse(&accessrequestv1.ListMyGrantsResponse{Grants: s.grants}), nil
}

func newAccessStub(t *testing.T, s *stubAccessRequest) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessrequestv1connect.NewAccessRequestServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// resetAccessFlags restores mutated package-global flag state between runs.
func resetAccessFlags() {
	flagOutput = "table"
	accessRequestRole = ""
	accessRequestReason = ""
	accessRequestDuration = ""
	accessListPending = false
	for _, spec := range []struct {
		cmd  *cobra.Command
		name string
	}{
		{accessRequestCmd, "role"},
		{accessRequestCmd, "reason"},
		{accessRequestCmd, "duration"},
		{accessListCmd, "pending-approvals"},
	} {
		if f := spec.cmd.Flags().Lookup(spec.name); f != nil {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
}

func TestAccessRequest(t *testing.T) {
	s := &stubAccessRequest{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	// UUIDs so asset/role resolution is a passthrough (no Catalog/Access stub).
	const (
		roleID  = "11111111-1111-1111-1111-111111111111"
		assetID = "33333333-3333-3333-3333-333333333333"
	)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"access", "request", "root@" + assetID,
		"--role", roleID,
		"--reason", "debugging prod",
		"--duration", "2h",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotRequest == nil {
		t.Fatalf("RequestAccess not called")
	}
	if s.gotRequest.GetAssetId() != assetID {
		t.Fatalf("asset_id=%q", s.gotRequest.GetAssetId())
	}
	if s.gotRequest.GetRoleId() != roleID {
		t.Fatalf("role_id=%q", s.gotRequest.GetRoleId())
	}
	if s.gotRequest.GetReason() != "debugging prod" {
		t.Fatalf("reason=%q", s.gotRequest.GetReason())
	}
	if s.gotRequest.GetDurationSeconds() != 7200 {
		t.Fatalf("duration_seconds=%d", s.gotRequest.GetDurationSeconds())
	}
	if !strings.Contains(out.String(), "req-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestAccessRequestRejectsNonUUIDAsset(t *testing.T) {
	s := &stubAccessRequest{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	const roleID = "11111111-1111-1111-1111-111111111111"

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{
		"access", "request", "root@deploy.pg.db.prod",
		"--role", roleID,
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-UUID asset ref, got nil")
	}
	if !strings.Contains(err.Error(), "takes the asset id") {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.gotRequest != nil {
		t.Fatal("RequestAccess should not have been called for a non-UUID asset ref")
	}
}

func TestAccessApprove(t *testing.T) {
	s := &stubAccessRequest{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"access", "approve", "req-xyz"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if s.gotApprove == nil || s.gotApprove.GetRequestId() != "req-xyz" {
		t.Fatalf("approve req=%+v", s.gotApprove)
	}
	if !strings.Contains(out.String(), "req-xyz") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestAccessDeny(t *testing.T) {
	s := &stubAccessRequest{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"access", "deny", "req-xyz"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if s.gotDeny == nil || s.gotDeny.GetRequestId() != "req-xyz" {
		t.Fatalf("deny req=%+v", s.gotDeny)
	}
}

func TestAccessList(t *testing.T) {
	s := &stubAccessRequest{requests: []*accessrequestv1.AccessRequest{
		{Id: "r-1", RoleId: "role-1", AssetId: "asset-1", Status: "pending", Reason: "why"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"access", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !s.calledListMyRequests {
		t.Fatalf("ListMyRequests not called")
	}
	if s.calledListPendingApproval {
		t.Fatalf("ListPendingApprovals should not have been called")
	}
	got := out.String()
	if !strings.Contains(got, "r-1") || !strings.Contains(got, "pending") {
		t.Fatalf("out=%s", got)
	}
}

func TestAccessListPendingApprovals(t *testing.T) {
	s := &stubAccessRequest{requests: []*accessrequestv1.AccessRequest{
		{Id: "r-2", RoleId: "role-2", AssetId: "asset-2", Status: "pending"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"access", "list", "--pending-approvals"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !s.calledListPendingApproval {
		t.Fatalf("ListPendingApprovals not called")
	}
	if s.calledListMyRequests {
		t.Fatalf("ListMyRequests should not have been called")
	}
}

func TestAccessGrants(t *testing.T) {
	s := &stubAccessRequest{grants: []*accessrequestv1.Grant{
		{Id: "g-1", RoleId: "role-1", AssetId: "asset-1", Active: true, ExpiresAt: "2026-01-01T00:00:00Z"},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAccessFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"access", "grants", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !s.calledListMyGrants {
		t.Fatalf("ListMyGrants not called")
	}
	got := out.String()
	if !strings.Contains(got, "g-1") || !strings.Contains(got, "2026-01-01T00:00:00Z") {
		t.Fatalf("out=%s", got)
	}
}
