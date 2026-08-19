package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	gossh "golang.org/x/crypto/ssh"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
)

func TestCatalogAdminCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// non-admin rejected
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "nope"}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateFolder = %v, want PermissionDenied", connect.CodeOf(err))
	}

	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: "pg-prod"}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assets, err := c.ListAssetsByFolder(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsByFolderRequest{FolderId: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(assets.Msg.Assets) != 1 || assets.Msg.Assets[0].Id != a.Msg.Asset.Id {
		t.Fatalf("list assets mismatch: %+v", assets.Msg.Assets)
	}
	folders, err := c.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list folders: %v", err)
	}
	if len(folders.Msg.Folders) < 1 {
		t.Fatalf("want >=1 folder")
	}
}

// TestCatalogCreateAssetWithSSHConfig covers the single-call onboard: CreateAsset
// with inline SSH config returns the config and GetAsset reads it back.
func TestCatalogCreateAssetWithSSHConfig(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "cfg"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	created, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: f.Msg.Folder.Id, Name: "box", Kind: "ssh",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfig{
			AllowedLogins: []string{"root", "deploy"}, AuthMethod: "ca-cert", TargetAddress: "10.0.0.9:22",
		}},
	}), tok))
	if err != nil {
		t.Fatalf("create asset with config: %v", err)
	}
	if s := created.Msg.Asset.GetSsh(); s == nil || s.AuthMethod != "ca-cert" || len(s.AllowedLogins) != 2 {
		t.Fatalf("create response config mismatch: %+v", created.Msg.Asset)
	}

	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: created.Msg.Asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	s := got.Msg.Asset.GetSsh()
	if s == nil || s.AuthMethod != "ca-cert" || len(s.AllowedLogins) != 2 ||
		s.AllowedLogins[0] != "root" || s.AllowedLogins[1] != "deploy" || s.TargetAddress != "10.0.0.9:22" {
		t.Fatalf("GetAsset config mismatch: %+v", got.Msg.Asset)
	}
	if s.StoredSecretId != "" {
		t.Fatalf("unexpected stored_secret_id: %q", s.StoredSecretId)
	}
}

// TestCatalogCreateAssetConfigRollsBack asserts CreateAsset with a bad inline config
// (stored-key without a secret violates the CHECK) rolls back the asset — no orphan.
func TestCatalogCreateAssetConfigRollsBack(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "rb"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	_, err = c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: f.Msg.Folder.Id, Name: "orphan", Kind: "ssh",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfig{AllowedLogins: []string{"root"}, AuthMethod: "stored-key"}},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("create with bad config = %v, want InvalidArgument", connect.CodeOf(err))
	}
	list, err := c.ListAssetsByFolder(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsByFolderRequest{FolderId: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Msg.Assets) != 0 {
		t.Fatalf("create rolled back but %d asset(s) remain: %+v", len(list.Msg.Assets), list.Msg.Assets)
	}
}

// TestCatalogUpdateAssetConfig covers UpdateAssetConfig upsert + the optional
// host_public_key contract (valid round-trips, empty clears, garbage rejected) and
// the stored-key-needs-secret CHECK.
func TestCatalogUpdateAssetConfig(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	hostKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))

	upd := func(ssh *catalogv1.SSHConfig) error {
		_, err := c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
			AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: ssh},
		}), tok))
		return err
	}

	if err := upd(&catalogv1.SSHConfig{AllowedLogins: []string{"root"}, AuthMethod: "ca-cert", HostPublicKey: hostKey, TargetAddress: "10.0.0.9:22"}); err != nil {
		t.Fatalf("update with host key: %v", err)
	}
	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if s := got.Msg.Asset.GetSsh(); s == nil || s.HostPublicKey != hostKey || s.TargetAddress != "10.0.0.9:22" {
		t.Fatalf("roundtrip mismatch: %+v", got.Msg.Asset)
	}

	if err := upd(&catalogv1.SSHConfig{AllowedLogins: []string{"root"}, AuthMethod: "ca-cert"}); err != nil {
		t.Fatalf("update clear: %v", err)
	}
	got2, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset (post-clear): %v", err)
	}
	if s := got2.Msg.Asset.GetSsh(); s == nil || s.HostPublicKey != "" || s.TargetAddress != "" {
		t.Fatalf("not cleared: %+v", got2.Msg.Asset)
	}

	if connect.CodeOf(upd(&catalogv1.SSHConfig{AllowedLogins: []string{"root"}, AuthMethod: "ca-cert", HostPublicKey: "not a key"})) != connect.CodeInvalidArgument {
		t.Fatal("bad host key not rejected InvalidArgument")
	}
	if connect.CodeOf(upd(&catalogv1.SSHConfig{AllowedLogins: []string{"root"}, AuthMethod: "stored-key"})) != connect.CodeInvalidArgument {
		t.Fatal("stored-key without secret not rejected InvalidArgument")
	}
}

// TestCatalogGetAsset covers an asset with no config (config omitted) and an
// unknown asset (NotFound).
func TestCatalogGetAsset(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got.Msg.Asset.GetSsh() != nil {
		t.Fatalf("expected no config, got %+v", got.Msg.Asset.GetSsh())
	}
	_, err = c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: "11111111-1111-1111-1111-111111111111"}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetAsset unknown = %v, want NotFound", connect.CodeOf(err))
	}
}

// TestCatalogAssetConfigRequiresAdmin locks the admin guard on the config reads/writes.
func TestCatalogAssetConfigRequiresAdmin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	_, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin GetAsset = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err = c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfig{AuthMethod: "ca-cert"}},
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin UpdateAssetConfig = %v, want PermissionDenied", connect.CodeOf(err))
	}
}
