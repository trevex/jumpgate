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

// stubAssets serves the catalog service. `assets ssh create` is a single
// CreateAsset call carrying the inline (ca) SSH logins; `assets ssh login set`
// is a GetAsset + UpdateAssetConfig read-modify-write (plus a vault seal for
// password/key kinds, served by stubVault).
type stubAssets struct {
	catalogv1connect.UnimplementedCatalogServiceHandler

	gotCreateAsset       *catalogv1.CreateAssetRequest
	gotUpdateAssetConfig *catalogv1.UpdateAssetConfigRequest

	// getAssetSSH is the config GetAsset returns (the current state the
	// read-modify-write starts from).
	getAssetSSH *catalogv1.SSHConfig

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

func (s *stubAssets) GetAsset(_ context.Context, req *connect.Request[catalogv1.GetAssetRequest]) (*connect.Response[catalogv1.GetAssetResponse], error) {
	asset := &catalogv1.Asset{Id: req.Msg.GetAssetId(), Kind: "ssh"}
	if s.getAssetSSH != nil {
		asset.Config = &catalogv1.Asset_Ssh{Ssh: s.getAssetSSH}
	}
	return connect.NewResponse(&catalogv1.GetAssetResponse{Asset: asset}), nil
}

func (s *stubAssets) UpdateAssetConfig(_ context.Context, req *connect.Request[catalogv1.UpdateAssetConfigRequest]) (*connect.Response[catalogv1.UpdateAssetConfigResponse], error) {
	s.gotUpdateAssetConfig = req.Msg
	return connect.NewResponse(&catalogv1.UpdateAssetConfigResponse{}), nil
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

// stubVault serves the vault service; SetAssetSecret records its request and
// returns a fixed sealed secret id.
type stubVault struct {
	vaultv1connect.UnimplementedVaultServiceHandler

	gotSetAssetSecret *vaultv1.SetAssetSecretRequest
	secretID          string
}

func (v *stubVault) SetAssetSecret(_ context.Context, req *connect.Request[vaultv1.SetAssetSecretRequest]) (*connect.Response[vaultv1.SetAssetSecretResponse], error) {
	v.gotSetAssetSecret = req.Msg
	return connect.NewResponse(&vaultv1.SetAssetSecretResponse{Id: v.secretID}), nil
}

// resetAssetsFlags restores mutated package-global flag state between runs so
// slice flags (which cobra accumulates into) do not leak across tests.
func resetAssetsFlags() {
	flagOutput = "table"
	sshCreateLogins = nil
	sshLoginName = ""
	sshLoginKind = ""
	sshLoginStdin = false
	sshLoginKeyFile = ""
	if f := assetsSSHCreateCmd.Flags().Lookup("login"); f != nil {
		_ = f.Value.(interface{ Replace([]string) error }).Replace(nil)
		f.Changed = false
	}
	for _, name := range []string{"login", "kind", "password-stdin", "key-file"} {
		if f := assetsSSHLoginSetCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}
	if f := assetsListCmd.Flags().Lookup("folder"); f != nil {
		f.Changed = false
	}
}

// newAssetsStub serves the catalog handler (and optionally the vault handler)
// off one server and returns its URL.
func newAssetsStub(t *testing.T, s *stubAssets, v *stubVault) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(catalogv1connect.NewCatalogServiceHandler(s))
	if v != nil {
		mux.Handle(vaultv1connect.NewVaultServiceHandler(v))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestAssetsSSHCreate(t *testing.T) {
	const folderID = "11111111-1111-1111-1111-111111111111"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "ssh", "create", "prod-box",
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

	// The inline SSH config (ca logins) rides on the single CreateAsset call.
	ssh := s.gotCreateAsset.GetSsh()
	if ssh == nil {
		t.Fatal("CreateAsset carried no ssh config")
	}
	logins := ssh.GetLogins()
	if len(logins) != 2 {
		t.Fatalf("logins=%v", logins)
	}
	if logins[0].GetLogin() != "root" || logins[0].GetKind() != "ca" {
		t.Fatalf("login[0]=%v", logins[0])
	}
	if logins[1].GetLogin() != "deploy" || logins[1].GetKind() != "ca" {
		t.Fatalf("login[1]=%v", logins[1])
	}
	if ssh.GetTargetAddress() != "10.0.0.5:22" {
		t.Fatalf("target=%q", ssh.GetTargetAddress())
	}
	if ssh.GetHostPublicKey() != "ssh-ed25519 AAA" {
		t.Fatalf("host key=%q", ssh.GetHostPublicKey())
	}

	if !strings.Contains(out.String(), "a-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestAssetsSSHCreateCommaSeparatedLogins(t *testing.T) {
	const folderID = "22222222-2222-2222-2222-222222222222"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "ssh", "create", "box",
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
	logins := ssh.GetLogins()
	if len(logins) != 2 || logins[0].GetLogin() != "a" || logins[1].GetLogin() != "b" {
		t.Fatalf("logins=%v", logins)
	}
}

func TestAssetsSSHLoginSetPassword(t *testing.T) {
	const assetID = "33333333-3333-3333-3333-333333333333"
	// The asset already has a ca login; adding a password login must preserve it.
	s := &stubAssets{getAssetSSH: &catalogv1.SSHConfig{
		TargetAddress: "h:22",
		HostPublicKey: "ssh-ed25519 AAA",
		Logins:        []*catalogv1.SSHLogin{{Login: "root", Kind: "ca"}},
	}}
	v := &stubVault{secretID: "sec-999"}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, v))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetIn(strings.NewReader("hunter2\n"))
	rootCmd.SetArgs([]string{
		"assets", "ssh", "login", "set", assetID,
		"--login", "deploy",
		"--kind", "password",
		"--password-stdin",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// The password was sealed under name=login, with the trailing newline trimmed.
	if v.gotSetAssetSecret == nil {
		t.Fatal("SetAssetSecret was not called")
	}
	if v.gotSetAssetSecret.GetAssetId() != assetID {
		t.Fatalf("secret asset id=%q", v.gotSetAssetSecret.GetAssetId())
	}
	if v.gotSetAssetSecret.GetName() != "deploy" {
		t.Fatalf("secret name=%q", v.gotSetAssetSecret.GetName())
	}
	if string(v.gotSetAssetSecret.GetValue()) != "hunter2" {
		t.Fatalf("secret value=%q", v.gotSetAssetSecret.GetValue())
	}

	// UpdateAssetConfig carries the new password login (with the sealed id) plus
	// the preserved ca login, and preserves host/target.
	upd := s.gotUpdateAssetConfig
	if upd == nil {
		t.Fatal("UpdateAssetConfig was not called")
	}
	cfg := upd.GetSsh()
	if cfg.GetTargetAddress() != "h:22" || cfg.GetHostPublicKey() != "ssh-ed25519 AAA" {
		t.Fatalf("host/target not preserved: %v", cfg)
	}
	if len(cfg.GetLogins()) != 2 {
		t.Fatalf("logins=%v", cfg.GetLogins())
	}
	var deploy *catalogv1.SSHLogin
	haveRoot := false
	for _, l := range cfg.GetLogins() {
		switch l.GetLogin() {
		case "deploy":
			deploy = l
		case "root":
			haveRoot = l.GetKind() == "ca"
		}
	}
	if !haveRoot {
		t.Fatalf("ca login 'root' was not preserved: %v", cfg.GetLogins())
	}
	if deploy == nil || deploy.GetKind() != "password" || deploy.GetSecretId() != "sec-999" {
		t.Fatalf("password login=%v", deploy)
	}
}

func TestAssetsSSHLoginSetPasswordRequiresStdin(t *testing.T) {
	const assetID = "33333333-3333-3333-3333-333333333333"
	s := &stubAssets{}
	v := &stubVault{secretID: "sec-1"}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, v))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs([]string{
		"assets", "ssh", "login", "set", assetID,
		"--login", "deploy",
		"--kind", "password",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error when --password-stdin is missing")
	}
	if v.gotSetAssetSecret != nil {
		t.Fatal("no secret should be sealed on a validation error")
	}
}

func TestAssetsSSHLoginList(t *testing.T) {
	const assetID = "44444444-4444-4444-4444-444444444444"
	s := &stubAssets{getAssetSSH: &catalogv1.SSHConfig{
		Logins: []*catalogv1.SSHLogin{
			{Login: "root", Kind: "ca"},
			{Login: "deploy", Kind: "password", SecretId: "sec-1"},
		},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"assets", "ssh", "login", "list", assetID, "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "root") || !strings.Contains(got, "ca") {
		t.Fatalf("out=%s", got)
	}
	if !strings.Contains(got, "deploy") || !strings.Contains(got, "password") {
		t.Fatalf("out=%s", got)
	}
	// Secret values must never be printed; secret ids are non-sensitive refs but
	// the list is intentionally LOGIN|KIND only.
	if strings.Contains(got, "sec-1") {
		t.Fatalf("login list leaked secret id: %s", got)
	}
}

func TestAssetsList(t *testing.T) {
	s := &stubAssets{visible: []*catalogv1.VisibleAsset{
		{Id: "a-1", Name: "prod-box", Active: true},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
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

func TestAssetsListByFolderPathColumn(t *testing.T) {
	const folderID = "55555555-5555-5555-5555-555555555555"
	s := &stubAssets{byFolder: []*catalogv1.Asset{
		{Id: "a-99", Name: "pg-primary", Kind: "ssh", FolderId: folderID, Path: "prod.db.pg-primary"},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"assets", "list", "--folder", folderID, "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "PATH") {
		t.Fatalf("assets table missing PATH column:\n%s", got)
	}
	if !strings.Contains(got, "prod.db.pg-primary") {
		t.Fatalf("assets table missing path value:\n%s", got)
	}
}

func TestAssetsSSHCreatePathColumn(t *testing.T) {
	const folderID = "66666666-6666-6666-6666-666666666666"
	s := &stubAssets{}
	// Use the existing stubAssets which returns an asset without a path (path
	// is empty). That is fine — we only assert the PATH header exists, not a
	// specific value, since this test focuses on the column being present.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s, nil))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "ssh", "create", "web",
		"--folder", folderID,
		"--target", "10.0.0.1:22",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "PATH") {
		t.Fatalf("assets ssh create table missing PATH column:\n%s", got)
	}
}
