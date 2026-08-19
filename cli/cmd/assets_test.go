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
)

// stubAssets serves the catalog service; onboarding is a single CreateAsset call
// carrying the inline SSH config.
type stubAssets struct {
	catalogv1connect.UnimplementedCatalogServiceHandler

	gotCreateAsset *catalogv1.CreateAssetRequest

	visible  []*catalogv1.VisibleAsset
	byFolder []*catalogv1.Asset
}

func (s *stubAssets) CreateAsset(_ context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	s.gotCreateAsset = req.Msg
	asset := &catalogv1.Asset{
		Id:       "a-123",
		FolderId: req.Msg.GetFolderId(),
		Name:     req.Msg.GetName(),
		Kind:     req.Msg.GetKind(),
	}
	if ssh := req.Msg.GetSsh(); ssh != nil {
		asset.Config = &catalogv1.Asset_Ssh{Ssh: ssh}
	}
	return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: asset}), nil
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

// newAssetsStub serves the catalog handler off one server.
func newAssetsStub(t *testing.T, s *stubAssets) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(catalogv1connect.NewCatalogServiceHandler(s))
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

	// The inline SSH config rides on the single CreateAsset call.
	ssh := s.gotCreateAsset.GetSsh()
	if ssh == nil {
		t.Fatal("CreateAsset carried no ssh config")
	}
	logins := ssh.GetAllowedLogins()
	if len(logins) != 2 || logins[0] != "root" || logins[1] != "deploy" {
		t.Fatalf("logins=%v", logins)
	}
	if ssh.GetTargetAddress() != "10.0.0.5:22" {
		t.Fatalf("target=%q", ssh.GetTargetAddress())
	}
	if ssh.GetHostPublicKey() != "ssh-ed25519 AAA" {
		t.Fatalf("host key=%q", ssh.GetHostPublicKey())
	}
	if ssh.GetAuthMethod() != "ca-cert" {
		t.Fatalf("auth method=%q", ssh.GetAuthMethod())
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
	ssh := s.gotCreateAsset.GetSsh()
	if ssh == nil {
		t.Fatal("CreateAsset carried no ssh config")
	}
	logins := ssh.GetAllowedLogins()
	if len(logins) != 2 || logins[0] != "a" || logins[1] != "b" {
		t.Fatalf("logins=%v", logins)
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
