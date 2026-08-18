package rpc_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
)

// TestVaultNilSealerFailsClosed locks the vault-disabled contract: the seal paths
// fail with FailedPrecondition (never nil-deref), and the admin guard still runs
// first (a non-admin is denied even with no sealer).
func TestVaultNilSealerFailsClosed(t *testing.T) {
	pool, url := newServerNoVault(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "user@x", "password123", false)
	atok := adminToken(t, url)
	utok := authClient(t, url, "user@x", "password123")
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Admin on a disabled vault: seal paths → FailedPrecondition.
	if _, err := c.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), atok)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("InitCA (nil sealer) = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	a := newAsset(t, url, atok, "ssh")
	if _, err := c.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: a.Id, Name: "pw", Value: []byte("x")}), atok)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("SetAssetSecret (nil sealer) = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	// Non-admin: the admin guard runs before the sealer check.
	if _, err := c.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("InitCA (non-admin, nil sealer) = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// newAsset creates a folder + asset (of the given kind) and returns the asset id.
func newAsset(t *testing.T, url, tok, kind string) *catalogv1.Asset {
	t.Helper()
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()
	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "vault-folder"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: "asset-" + kind, Kind: kind}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	return a.Msg.Asset
}

func TestVaultRequiresAdmin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")

	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	assertDenied := func(name string, err error) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s non-admin = %v, want PermissionDenied", name, connect.CodeOf(err))
		}
	}

	_, err := c.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), utok))
	assertDenied("InitCA", err)
	_, err = c.GetCAPublic(ctx, withToken(connect.NewRequest(&vaultv1.GetCAPublicRequest{Kind: "ssh"}), utok))
	assertDenied("GetCAPublic", err)
	_, err = c.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: "00000000-0000-0000-0000-000000000000", Name: "x", Value: []byte("y")}), utok))
	assertDenied("SetAssetSecret", err)
	_, err = c.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: "00000000-0000-0000-0000-000000000000"}), utok))
	assertDenied("DeleteAssetSecret", err)
	_, err = c.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: "00000000-0000-0000-0000-000000000000"}), utok))
	assertDenied("ListAssetSecrets", err)
	_, err = c.SetSSHAssetConfig(ctx, withToken(connect.NewRequest(&vaultv1.SetSSHAssetConfigRequest{AssetId: "00000000-0000-0000-0000-000000000000", AuthMethod: "ca-cert"}), utok))
	assertDenied("SetSSHAssetConfig", err)
	_, err = c.GetSSHAssetConfig(ctx, withToken(connect.NewRequest(&vaultv1.GetSSHAssetConfigRequest{AssetId: "00000000-0000-0000-0000-000000000000"}), utok))
	assertDenied("GetSSHAssetConfig", err)
}

func TestVaultInitCA(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	for _, kind := range []string{"ssh", "x509"} {
		resp, err := c.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: kind}), tok))
		if err != nil {
			t.Fatalf("InitCA(%s): %v", kind, err)
		}
		if resp.Msg.PublicMaterial == "" {
			t.Fatalf("InitCA(%s): empty public_material", kind)
		}
		// A second init for the same kind hits uq_active_ca → AlreadyExists.
		_, err = c.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: kind}), tok))
		if connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Fatalf("InitCA(%s) 2nd = %v, want AlreadyExists", kind, connect.CodeOf(err))
		}
		// GetCAPublic returns the same material.
		got, err := c.GetCAPublic(ctx, withToken(connect.NewRequest(&vaultv1.GetCAPublicRequest{Kind: kind}), tok))
		if err != nil {
			t.Fatalf("GetCAPublic(%s): %v", kind, err)
		}
		if got.Msg.PublicMaterial != resp.Msg.PublicMaterial {
			t.Fatalf("GetCAPublic(%s) mismatch", kind)
		}
	}
}

func TestVaultGetCAPublicNotFound(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)

	_, err := c.GetCAPublic(context.Background(), withToken(connect.NewRequest(&vaultv1.GetCAPublicRequest{Kind: "ssh"}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetCAPublic (no CA) = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestVaultAssetSecrets(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")

	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	set, err := c.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{
		AssetId: asset.Id, Name: "db-pw", Value: []byte("s3cr3t"),
	}), tok))
	if err != nil {
		t.Fatalf("SetAssetSecret: %v", err)
	}
	if set.Msg.Id == "" {
		t.Fatal("SetAssetSecret: empty id")
	}

	list, err := c.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("ListAssetSecrets: %v", err)
	}
	if len(list.Msg.Secrets) != 1 || list.Msg.Secrets[0].Name != "db-pw" {
		t.Fatalf("ListAssetSecrets mismatch: %+v", list.Msg.Secrets)
	}
	if list.Msg.Secrets[0].Id != set.Msg.Id {
		t.Fatalf("ListAssetSecrets id mismatch")
	}
	if list.Msg.Secrets[0].CreatedAt == "" {
		t.Fatal("ListAssetSecrets: empty created_at")
	}

	// Deleting the secret empties the list.
	if _, err := c.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: set.Msg.Id}), tok)); err != nil {
		t.Fatalf("DeleteAssetSecret: %v", err)
	}
	list2, err := c.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("ListAssetSecrets (post-delete): %v", err)
	}
	if len(list2.Msg.Secrets) != 0 {
		t.Fatalf("post-delete list not empty: %+v", list2.Msg.Secrets)
	}
}

// TestAssetSecretMetaHasNoValue asserts the generated AssetSecretMeta exposes
// metadata only — no sealed value ever reaches a client. It reflects over the
// message's exported fields so an accidental future `value`/`sealed` field is
// caught here rather than leaking a secret.
func TestAssetSecretMetaHasNoValue(t *testing.T) {
	typ := reflect.TypeOf(vaultv1.AssetSecretMeta{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if name == "value" || name == "sealed" || name == "secret" {
			t.Fatalf("AssetSecretMeta must not expose a %q field (metadata only)", name)
		}
	}
}

func TestVaultSSHAssetConfig(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")

	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	if _, err := c.SetSSHAssetConfig(ctx, withToken(connect.NewRequest(&vaultv1.SetSSHAssetConfigRequest{
		AssetId: asset.Id, AllowedLogins: []string{"root", "deploy"}, AuthMethod: "ca-cert",
	}), tok)); err != nil {
		t.Fatalf("SetSSHAssetConfig ca-cert: %v", err)
	}

	got, err := c.GetSSHAssetConfig(ctx, withToken(connect.NewRequest(&vaultv1.GetSSHAssetConfigRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetSSHAssetConfig: %v", err)
	}
	if got.Msg.AuthMethod != "ca-cert" || len(got.Msg.AllowedLogins) != 2 ||
		got.Msg.AllowedLogins[0] != "root" || got.Msg.AllowedLogins[1] != "deploy" {
		t.Fatalf("GetSSHAssetConfig round-trip mismatch: %+v", got.Msg)
	}
	if got.Msg.StoredSecretId != "" {
		t.Fatalf("unexpected stored_secret_id: %q", got.Msg.StoredSecretId)
	}

	// stored-key without a secret violates the stored_key_needs_secret CHECK.
	_, err = c.SetSSHAssetConfig(ctx, withToken(connect.NewRequest(&vaultv1.SetSSHAssetConfigRequest{
		AssetId: asset.Id, AllowedLogins: []string{"root"}, AuthMethod: "stored-key",
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("SetSSHAssetConfig stored-key (no secret) = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestVaultGetSSHAssetConfigNotFound(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)

	_, err := c.GetSSHAssetConfig(context.Background(), withToken(connect.NewRequest(&vaultv1.GetSSHAssetConfigRequest{AssetId: asset.Id}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetSSHAssetConfig (absent) = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestCreateAssetKind(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)

	// Explicit kind persists.
	pg := newAsset(t, url, tok, "postgres")
	if pg.Kind != "postgres" {
		t.Fatalf("CreateAsset(kind=postgres) got kind %q", pg.Kind)
	}

	// Empty kind defaults to "ssh".
	def := newAsset(t, url, tok, "")
	if def.Kind != "ssh" {
		t.Fatalf("CreateAsset(kind=\"\") got kind %q, want ssh", def.Kind)
	}
}
