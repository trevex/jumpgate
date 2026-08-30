package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

// stubAssets serves the catalog service. `assets ssh create` is a single
// CreateAsset call carrying the inline (ca) SSH logins; `assets ssh login set`
// is a GetAsset + UpdateAssetConfig read-modify-write where password/key secrets
// ride inline as new_value and are sealed server-side in-tx (no vault round-trip).
type stubAssets struct {
	catalogv1connect.UnimplementedCatalogServiceHandler

	gotCreateAsset       *catalogv1.CreateAssetRequest
	gotUpdateAssetConfig *catalogv1.UpdateAssetConfigRequest

	// createAssetOverride, when non-nil, is returned verbatim by CreateAsset
	// instead of the default constructed asset.  Use this to inject fields (e.g.
	// Path) that the default stub does not set.
	createAssetOverride *catalogv1.Asset

	// getAssetSSH is the config GetAsset returns (the current state the
	// read-modify-write starts from).
	getAssetSSH *catalogv1.SSHConfig

	// getAccessOverride, when non-nil, is returned verbatim by GetAssetAccess.
	getAccessOverride *catalogv1.GetAssetAccessResponse

	// listed is returned by ListAssets (single page, empty NextPageToken).
	listed []*catalogv1.Asset
}

func (s *stubAssets) CreateAsset(_ context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	s.gotCreateAsset = req.Msg
	if s.createAssetOverride != nil {
		return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: s.createAssetOverride}), nil
	}
	asset := &catalogv1.Asset{
		Id:       "a-123",
		FolderId: req.Msg.GetFolderId(),
		Name:     req.Msg.GetName(),
		Kind:     "ssh",
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

func (s *stubAssets) ListAssets(_ context.Context, _ *connect.Request[catalogv1.ListAssetsRequest]) (*connect.Response[catalogv1.ListAssetsResponse], error) {
	return connect.NewResponse(&catalogv1.ListAssetsResponse{Assets: s.listed}), nil
}

// getAccessOverride, when non-nil, is returned verbatim by GetAssetAccess.
func (s *stubAssets) GetAssetAccess(_ context.Context, _ *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	if s.getAccessOverride != nil {
		return connect.NewResponse(s.getAccessOverride), nil
	}
	return connect.NewResponse(&catalogv1.GetAssetAccessResponse{
		ActiveRoleIds:      []string{"role-active-id"},
		RequestableRoleIds: []string{"role-req-id"},
		ActiveRoles:        []*catalogv1.RoleRef{{Id: "role-active-id", Name: "shell", FolderPath: "prod"}},
		RequestableRoles:   []*catalogv1.RoleRef{{Id: "role-req-id", Name: "admin"}},
	}), nil
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
	if f := assetsListCmd.Flags().Lookup("cascade"); f != nil {
		f.Changed = false
	}
	assetsListCascade = false
}

// newAssetsStub serves the catalog handler off one server and returns its URL.
// Secrets are sealed server-side in-tx as part of UpdateAssetConfig now, so the
// CLI no longer makes a separate VaultService round-trip on the create/rotate path.
func newAssetsStub(t *testing.T, s *stubAssets) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(catalogv1connect.NewCatalogServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestAssetsSSHCreate(t *testing.T) {
	const folderID = "11111111-1111-1111-1111-111111111111"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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

	// The inline SSH config (ca logins) rides on the single CreateAsset call.
	ssh := s.gotCreateAsset.GetSsh()
	if ssh == nil {
		t.Fatal("CreateAsset carried no ssh config")
	}
	logins := ssh.GetLogins()
	if len(logins) != 2 {
		t.Fatalf("logins=%v", logins)
	}
	if logins[0].GetLogin() != "root" || sshLoginInputKind(logins[0]) != "ca" {
		t.Fatalf("login[0]=%v", logins[0])
	}
	if logins[1].GetLogin() != "deploy" || sshLoginInputKind(logins[1]) != "ca" {
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

func TestAssetsK8sCreate(t *testing.T) {
	const folderID = "22222222-2222-2222-2222-222222222222"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "k8s", "create", "prod-cluster",
		"--folder", folderID,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateAsset == nil {
		t.Fatal("CreateAsset not called")
	}
	if s.gotCreateAsset.GetFolderId() != folderID {
		t.Fatalf("folder id=%q", s.gotCreateAsset.GetFolderId())
	}
	if s.gotCreateAsset.GetName() != "prod-cluster" {
		t.Fatalf("name=%q", s.gotCreateAsset.GetName())
	}
	if s.gotCreateAsset.GetKubernetes() == nil {
		t.Fatalf("expected kubernetes config arm, got %T", s.gotCreateAsset.GetConfig())
	}

	if !strings.Contains(out.String(), "a-123") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestAssetsSSHCreateCommaSeparatedLogins(t *testing.T) {
	const folderID = "22222222-2222-2222-2222-222222222222"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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

	// UpdateAssetConfig carries the new password login (with the plaintext secret
	// inlined as new_value, sealed server-side in-tx) plus the preserved ca login,
	// and preserves host/target. No separate vault round-trip happens anymore.
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
	var deploy *catalogv1.SSHLoginInput
	haveRoot := false
	for _, l := range cfg.GetLogins() {
		switch l.GetLogin() {
		case "deploy":
			deploy = l
		case "root":
			haveRoot = sshLoginInputKind(l) == "ca"
		}
	}
	if !haveRoot {
		t.Fatalf("ca login 'root' was not preserved: %v", cfg.GetLogins())
	}
	if deploy == nil || sshLoginInputKind(deploy) != "password" {
		t.Fatalf("password login=%v", deploy)
	}
	// The trailing newline is trimmed; the plaintext rides as new_value, not a ref.
	if string(deploy.GetPassword().GetNewValue()) != "hunter2" {
		t.Fatalf("password new_value=%q", deploy.GetPassword().GetNewValue())
	}
	if deploy.GetPassword().GetExistingSecretId() != "" {
		t.Fatalf("password should carry new_value, not an existing id: %v", deploy.GetPassword())
	}
}

func TestAssetsSSHLoginSetPasswordRequiresStdin(t *testing.T) {
	const assetID = "33333333-3333-3333-3333-333333333333"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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
	// Validation fails before any RPC, so UpdateAssetConfig is never reached.
	if s.gotUpdateAssetConfig != nil {
		t.Fatal("no config update should happen on a validation error")
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
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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
	s := &stubAssets{listed: []*catalogv1.Asset{
		{Id: "a-1", Name: "prod-box", Kind: "ssh", Path: "prod-box.prod"},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	if !strings.Contains(got, "a-1") || !strings.Contains(got, "prod-box.prod") {
		t.Fatalf("out=%s", got)
	}
	if !strings.Contains(got, "PATH") {
		t.Fatalf("assets list table missing PATH column:\n%s", got)
	}
}

func TestAssetsGet(t *testing.T) {
	const assetID = "44444444-4444-4444-4444-444444444444"
	s := &stubAssets{}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	// Roles render by NAME (a folder-scoped role is suffixed with its path), not by id.
	if !strings.Contains(got, "shell.prod") {
		t.Fatalf("active role name missing: %s", got)
	}
	if !strings.Contains(got, "admin") {
		t.Fatalf("requestable role name missing: %s", got)
	}
}

// TestAssetsGetRoleNameFallback covers an older server that returns only id lists
// (no RoleRef): the ids are rendered as-is.
func TestAssetsGetRoleNameFallback(t *testing.T) {
	const assetID = "44444444-4444-4444-4444-444444444444"
	s := &stubAssets{getAccessOverride: &catalogv1.GetAssetAccessResponse{
		ActiveRoleIds:      []string{"role-active-id"},
		RequestableRoleIds: []string{"role-req-id"},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	if !strings.Contains(got, "role-active-id") || !strings.Contains(got, "role-req-id") {
		t.Fatalf("id fallback not rendered: %s", got)
	}
}

func TestAssetsListWithParentPathColumn(t *testing.T) {
	const folderID = "55555555-5555-5555-5555-555555555555"
	s := &stubAssets{listed: []*catalogv1.Asset{
		{Id: "a-99", Name: "pg-primary", Kind: "ssh", FolderId: folderID, Path: "pg-primary.db.prod"},
	}}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	// Pass a parent path positional argument and --cascade to exercise both new UX paths.
	rootCmd.SetArgs([]string{"assets", "list", "db.prod", "--cascade", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "PATH") {
		t.Fatalf("assets table missing PATH column:\n%s", got)
	}
	if !strings.Contains(got, "pg-primary.db.prod") {
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
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
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

// TestAssetsSSHCreateJSONHasIDAndPath guarantees that `assets ssh create -o json`
// emits both "id" and "path" fields so provisioning automation can read them
// from `jumpgate assets ssh create -o json` without fragility.
func TestAssetsSSHCreateJSONHasIDAndPath(t *testing.T) {
	const folderID = "77777777-7777-7777-7777-777777777777"
	s := &stubAssets{
		createAssetOverride: &catalogv1.Asset{
			Id:       "a1",
			Name:     "web",
			Kind:     "ssh",
			FolderId: "f1",
			Path:     "web.db.prod",
		},
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JUMPGATE_WARDEN_ADDR", newAssetsStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(resetAssetsFlags)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{
		"assets", "ssh", "create", "web",
		"--folder", folderID,
		"--target", "10.0.0.1:22",
		"--login", "deploy",
		"-o", "json",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var got struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("create output not JSON: %v\n%s", err, out.String())
	}
	if got.ID == "" || got.Path == "" {
		t.Fatalf("create JSON missing id/path for automation: id=%q path=%q\n%s", got.ID, got.Path, out.String())
	}
}
