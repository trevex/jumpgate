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
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

// stubAccessCatalog serves the catalog RPCs the access-request flow needs:
// ResolveAsset (path|uuid -> asset id) and GetAssetAccess (requestable roles).
type stubAccessCatalog struct {
	catalogv1connect.UnimplementedCatalogServiceHandler

	assetID          string
	gotResolveRef    string
	gotAccessAssetID string
	requestableRoles []*catalogv1.RoleRef
}

func (c *stubAccessCatalog) ResolveAsset(_ context.Context, req *connect.Request[catalogv1.ResolveAssetRequest]) (*connect.Response[catalogv1.ResolveAssetResponse], error) {
	c.gotResolveRef = req.Msg.GetRef()
	return connect.NewResponse(&catalogv1.ResolveAssetResponse{AssetId: c.assetID, Path: req.Msg.GetRef()}), nil
}

func (c *stubAccessCatalog) GetAssetAccess(_ context.Context, req *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	c.gotAccessAssetID = req.Msg.GetAssetId()
	return connect.NewResponse(&catalogv1.GetAssetAccessResponse{RequestableRoles: c.requestableRoles}), nil
}

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
	return newAccessStubWithCatalog(t, s, nil)
}

// newAccessStubWithCatalog wires the access-request stub and, when non-nil, a
// catalog stub (for the name/path resolution path) into one test server.
func newAccessStubWithCatalog(t *testing.T, s *stubAccessRequest, cat *stubAccessCatalog) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessrequestv1connect.NewAccessRequestServiceHandler(s))
	if cat != nil {
		mux.Handle(catalogv1connect.NewCatalogServiceHandler(cat))
	}
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

func TestAccessRequestResolvesNames(t *testing.T) {
	const fixedAssetID = "33333333-3333-3333-3333-333333333333"

	t.Run("resolves asset path + role name to ids", func(t *testing.T) {
		s := &stubAccessRequest{}
		cat := &stubAccessCatalog{
			assetID:          fixedAssetID,
			requestableRoles: []*catalogv1.RoleRef{{Id: "role-uuid-1", Name: "ssh-deploy"}},
		}
		t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStubWithCatalog(t, s, cat))
		t.Setenv("JUMPGATE_TOKEN", "tok")
		t.Cleanup(resetAccessFlags)

		rootCmd.SetOut(&bytes.Buffer{})
		rootCmd.SetArgs([]string{
			"access", "request", "deploy@demo-box.demo",
			"--role", "ssh-deploy",
		})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}

		if cat.gotResolveRef != "demo-box.demo" {
			t.Fatalf("ResolveAsset ref=%q, want demo-box.demo (login stripped)", cat.gotResolveRef)
		}
		if s.gotRequest == nil {
			t.Fatalf("RequestAccess not called")
		}
		if s.gotRequest.GetAssetId() != fixedAssetID {
			t.Fatalf("asset_id=%q, want %q", s.gotRequest.GetAssetId(), fixedAssetID)
		}
		if s.gotRequest.GetRoleId() != "role-uuid-1" {
			t.Fatalf("role_id=%q, want role-uuid-1", s.gotRequest.GetRoleId())
		}
	})

	t.Run("unknown role name errors before RequestAccess", func(t *testing.T) {
		s := &stubAccessRequest{}
		cat := &stubAccessCatalog{
			assetID:          fixedAssetID,
			requestableRoles: []*catalogv1.RoleRef{{Id: "role-uuid-1", Name: "ssh-deploy"}},
		}
		t.Setenv("JUMPGATE_WARDEN_ADDR", newAccessStubWithCatalog(t, s, cat))
		t.Setenv("JUMPGATE_TOKEN", "tok")
		t.Cleanup(resetAccessFlags)

		rootCmd.SetOut(&bytes.Buffer{})
		rootCmd.SetArgs([]string{
			"access", "request", "deploy@demo-box.demo",
			"--role", "no-such",
		})
		err := rootCmd.Execute()
		if err == nil {
			t.Fatal("expected error for unknown role name, got nil")
		}
		if !strings.Contains(err.Error(), "not requestable") {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.gotRequest != nil {
			t.Fatal("RequestAccess should not have been called for an unknown role name")
		}
	})
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

func TestMatchRequestableRole(t *testing.T) {
	global := &catalogv1.RoleRef{Id: "g1", Name: "shell"}
	scoped := &catalogv1.RoleRef{Id: "s1", Name: "shell", FolderPath: "prod"}

	tests := []struct {
		name    string
		refs    []*catalogv1.RoleRef
		ref     string
		wantID  string
		wantErr string
	}{
		{
			name:   "bare name single global",
			refs:   []*catalogv1.RoleRef{global},
			ref:    "shell",
			wantID: "g1",
		},
		{
			name:    "bare name ambiguous",
			refs:    []*catalogv1.RoleRef{global, scoped},
			ref:     "shell",
			wantErr: "ambiguous",
		},
		{
			name:   "qualified picks scoped only",
			refs:   []*catalogv1.RoleRef{global, scoped},
			ref:    "shell.prod",
			wantID: "s1",
		},
		{
			name:    "unknown not requestable",
			refs:    []*catalogv1.RoleRef{global, scoped},
			ref:     "nope",
			wantErr: "not requestable",
		},
		{
			name:   "scoped by qualified when alone",
			refs:   []*catalogv1.RoleRef{scoped},
			ref:    "shell.prod",
			wantID: "s1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := matchRequestableRole(tt.refs, tt.ref, "pg-primary.db.prod")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got id=%q nil err", tt.wantErr, id)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%q want containing %q", err.Error(), tt.wantErr)
				}
				if id != "" {
					t.Fatalf("want empty id on error, got %q", id)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if id != tt.wantID {
				t.Fatalf("id=%q want %q", id, tt.wantID)
			}
		})
	}
}
