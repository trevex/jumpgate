package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
)

// stubAssets serves both the catalog and vault services so the composite
// onboard flow can be exercised end-to-end against one server.
type stubAssets struct {
	catalogv1connect.UnimplementedCatalogServiceHandler
	vaultv1connect.UnimplementedVaultServiceHandler

	gotCreateAsset *catalogv1.CreateAssetRequest
	gotSSHConfig   *vaultv1.SetSSHAssetConfigRequest

	sshConfigErr error
	visible      []*catalogv1.VisibleAsset
	byFolder     []*catalogv1.Asset
}

func (s *stubAssets) CreateAsset(_ context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	s.gotCreateAsset = req.Msg
	return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: &catalogv1.Asset{
		Id:       "a-123",
		FolderId: req.Msg.GetFolderId(),
		Name:     req.Msg.GetName(),
		Kind:     req.Msg.GetKind(),
	}}), nil
}

func (s *stubAssets) ListVisibleAssets(_ context.Context, _ *connect.Request[catalogv1.ListVisibleAssetsRequest]) (*connect.Response[catalogv1.ListVisibleAssetsResponse], error) {
	return connect.NewResponse(&catalogv1.ListVisibleAssetsResponse{Assets: s.visible}), nil
}

func (s *stubAssets) ListAssetsByFolder(_ context.Context, _ *connect.Request[catalogv1.ListAssetsByFolderRequest]) (*connect.Response[catalogv1.ListAssetsByFolderResponse], error) {
	return connect.NewResponse(&catalogv1.ListAssetsByFolderResponse{Assets: s.byFolder}), nil
}

func (s *stubAssets) GetAssetAccess(_ context.Context, _ *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	return connect.NewResponse(&catalogv1.GetAssetAccessResponse{
		ActiveRoleIds:      []string{"role-active"},
		RequestableRoleIds: []string{"role-req"},
	}), nil
}

func (s *stubAssets) SetSSHAssetConfig(_ context.Context, req *connect.Request[vaultv1.SetSSHAssetConfigRequest]) (*connect.Response[vaultv1.SetSSHAssetConfigResponse], error) {
	s.gotSSHConfig = req.Msg
	if s.sshConfigErr != nil {
		return nil, s.sshConfigErr
	}
	return connect.NewResponse(&vaultv1.SetSSHAssetConfigResponse{}), nil
}

// resetAssetsFlags restores mutated package-global flag state between runs so
// slice flags (which cobra accumulates into) do not leak across tests.
func resetAssetsFlags() {
	flagOutput = "table"
	onboardSSHLogins = nil
	if f := assetsOnboardSSHCmd.Flags().Lookup("login"); f != nil {
		_ = f.Value.(interface{ Replace([]string) error }).Replace(nil)
		f.Changed = false
	}
	if f := assetsListCmd.Flags().Lookup("folder"); f != nil {
		f.Changed = false
	}
}

// newAssetsStub serves both catalog and vault handlers off one server.
func newAssetsStub(t *testing.T, s *stubAssets) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(catalogv1connect.NewCatalogServiceHandler(s))
	mux.Handle(vaultv1connect.NewVaultServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestAssetsOnboardSSH(t *testing.T) {
	const folderID = "11111111-1111-1111-1111-111111111111"
	s := &stubAssets{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "onboard", "ssh", "prod-box",
		"--folder", folderID,
		"--target", "10.0.0.5:22",
		"--login", "root",
		"--login", "deploy",
		"--host-key", "ssh-ed25519 AAA",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateAsset.GetFolderId() != folderID {
		t.Fatalf("folder id=%q", s.gotCreateAsset.GetFolderId())
	}
	if s.gotCreateAsset.GetName() != "prod-box" {
		t.Fatalf("name=%q", s.gotCreateAsset.GetName())
	}
	if s.gotCreateAsset.GetKind() != "ssh" {
		t.Fatalf("kind=%q", s.gotCreateAsset.GetKind())
	}

	if s.gotSSHConfig.GetAssetId() != "a-123" {
		t.Fatalf("config asset id=%q", s.gotSSHConfig.GetAssetId())
	}
	logins := s.gotSSHConfig.GetAllowedLogins()
	if len(logins) != 2 || logins[0] != "root" || logins[1] != "deploy" {
		t.Fatalf("logins=%v", logins)
	}
	if s.gotSSHConfig.GetTargetAddress() != "10.0.0.5:22" {
		t.Fatalf("target=%q", s.gotSSHConfig.GetTargetAddress())
	}
	if s.gotSSHConfig.GetHostPublicKey() != "ssh-ed25519 AAA" {
		t.Fatalf("host key=%q", s.gotSSHConfig.GetHostPublicKey())
	}
	if s.gotSSHConfig.GetAuthMethod() != "ca-cert" {
		t.Fatalf("auth method=%q", s.gotSSHConfig.GetAuthMethod())
	}

	if !strings.Contains(out.String(), "a-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestAssetsOnboardSSHCommaSeparatedLogins(t *testing.T) {
	const folderID = "22222222-2222-2222-2222-222222222222"
	s := &stubAssets{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "onboard", "ssh", "box",
		"--folder", folderID,
		"--target", "h:22",
		"--login", "a,b",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	logins := s.gotSSHConfig.GetAllowedLogins()
	if len(logins) != 2 || logins[0] != "a" || logins[1] != "b" {
		t.Fatalf("logins=%v", logins)
	}
}

func TestAssetsOnboardSSHConfigFailsAfterCreate(t *testing.T) {
	const folderID = "33333333-3333-3333-3333-333333333333"
	s := &stubAssets{sshConfigErr: connect.NewError(connect.CodeInternal, nil)}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{
		"assets", "onboard", "ssh", "box",
		"--folder", folderID,
		"--target", "h:22",
		"--login", "root",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error when ssh config fails")
	}
	msg := err.Error()
	// The error must make clear the asset WAS created (with its id) so the user
	// can retry only the config step.
	if !strings.Contains(msg, "a-123") || !strings.Contains(strings.ToLower(msg), "created") {
		t.Fatalf("error should name the created asset id and say it was created: %v", err)
	}
}

func TestAssetsList(t *testing.T) {
	s := &stubAssets{visible: []*catalogv1.VisibleAsset{
		{Id: "a-1", Name: "prod-box", Active: true},
	}}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"assets", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "a-1") || !strings.Contains(got, "prod-box") {
		t.Fatalf("out=%s", got)
	}
}

func TestAssetsGet(t *testing.T) {
	const assetID = "44444444-4444-4444-4444-444444444444"
	s := &stubAssets{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"assets", "get", assetID, "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "role-active") || !strings.Contains(got, "role-req") {
		t.Fatalf("out=%s", got)
	}
}
