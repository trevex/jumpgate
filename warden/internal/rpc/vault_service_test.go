package rpc_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
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
// Each call uses a unique folder name so multiple calls within a single test do not
// collide on the catalog_names uniqueness constraint.
func newAsset(t *testing.T, url, tok, kind string) *catalogv1.Asset {
	t.Helper()
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()
	folderName := "f-" + uuid.New().String()
	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: folderName}), tok))
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

// csrPEM generates a fresh CSR for the given spiffe id and returns it PEM-encoded.
func csrPEM(t *testing.T, spiffeID string) []byte {
	t.Helper()
	_, csrDER, err := ca.GenerateCSR(spiffeID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func TestInitMeshCAAndIssue(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	initResp, err := c.InitMeshCA(ctx, withToken(connect.NewRequest(&vaultv1.InitMeshCARequest{}), tok))
	if err != nil {
		t.Fatalf("InitMeshCA: %v", err)
	}
	if len(initResp.Msg.CaCertPem) == 0 {
		t.Fatal("InitMeshCA: empty ca_cert_pem")
	}

	const spiffeID = "spiffe://jumpgate/worker/w1"
	issueResp, err := c.IssueMeshCert(ctx, withToken(connect.NewRequest(&vaultv1.IssueMeshCertRequest{
		CsrPem:   csrPEM(t, spiffeID),
		SpiffeId: spiffeID,
	}), tok))
	if err != nil {
		t.Fatalf("IssueMeshCert: %v", err)
	}

	// Leaf parses.
	leafBlk, _ := pem.Decode(issueResp.Msg.CertPem)
	if leafBlk == nil {
		t.Fatal("IssueMeshCert: cert_pem is not PEM")
	}
	leaf, err := x509.ParseCertificate(leafBlk.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	// Carries the URI SAN.
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffeID {
		t.Fatalf("leaf URIs = %v, want [%s]", leaf.URIs, spiffeID)
	}
	// Chains to the returned bundle.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issueResp.Msg.CaBundlePem) {
		t.Fatal("ca_bundle_pem not usable as roots")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to bundle: %v", err)
	}

	// A second InitMeshCA hits uq_active_ca → AlreadyExists.
	_, err = c.InitMeshCA(ctx, withToken(connect.NewRequest(&vaultv1.InitMeshCARequest{}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("InitMeshCA 2nd = %v, want AlreadyExists", connect.CodeOf(err))
	}
}

func TestIssueMeshCertBadSpiffe(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	if _, err := c.InitMeshCA(ctx, withToken(connect.NewRequest(&vaultv1.InitMeshCARequest{}), tok)); err != nil {
		t.Fatalf("InitMeshCA: %v", err)
	}
	// A non-spiffe URI is rejected by mesh.ParseIdentity → InvalidArgument.
	_, err := c.IssueMeshCert(ctx, withToken(connect.NewRequest(&vaultv1.IssueMeshCertRequest{
		CsrPem:   csrPEM(t, "spiffe://jumpgate/worker/w1"),
		SpiffeId: "https://x/y/z",
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("IssueMeshCert bad spiffe = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestIssueMeshCertRequiresAdmin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	if _, err := c.InitMeshCA(ctx, withToken(connect.NewRequest(&vaultv1.InitMeshCARequest{}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("InitMeshCA non-admin = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err := c.IssueMeshCert(ctx, withToken(connect.NewRequest(&vaultv1.IssueMeshCertRequest{
		CsrPem:   csrPEM(t, "spiffe://jumpgate/worker/w1"),
		SpiffeId: "spiffe://jumpgate/worker/w1",
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("IssueMeshCert non-admin = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestIssueMeshCertNoMeshCA(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Without InitMeshCA, issuing fails FailedPrecondition.
	_, err := c.IssueMeshCert(ctx, withToken(connect.NewRequest(&vaultv1.IssueMeshCertRequest{
		CsrPem:   csrPEM(t, "spiffe://jumpgate/worker/w1"),
		SpiffeId: "spiffe://jumpgate/worker/w1",
	}), tok))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("IssueMeshCert without mesh CA = %v, want FailedPrecondition", connect.CodeOf(err))
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

// bindScopedCap creates a fresh role carrying capsJSON and binds it to the user
// at the given scope (asset if assetID non-nil, else folder if folderID non-nil,
// else global). It mirrors the manual bindings used across the rpc tests.
func bindScopedCap(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, capsJSON string, folderID, assetID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "cap-" + uuid.NewString(), Capabilities: []byte(capsJSON)})
	if err != nil {
		t.Fatalf("bindScopedCap CreateRole: %v", err)
	}
	params := gen.CreateRoleBindingParams{RoleID: role.ID, SubjectUserID: pgtype.UUID{Bytes: userID, Valid: true}}
	if assetID != uuid.Nil {
		params.ScopeAssetID = pgtype.UUID{Bytes: assetID, Valid: true}
	} else if folderID != uuid.Nil {
		params.ScopeFolderID = pgtype.UUID{Bytes: folderID, Valid: true}
	}
	if _, err := q.CreateRoleBinding(ctx, params); err != nil {
		t.Fatalf("bindScopedCap CreateRoleBinding: %v", err)
	}
}

// TestVaultCapabilityGating asserts the vault handlers are gated by scoped
// management capabilities, not a blanket admin flag: a user holding
// vault:secret:write at asset A's folder can SetAssetSecret on A but not on an
// unrelated asset B, and cannot InitCA (which needs vault:ca:init globally). The
// bootstrap admin (**) can do all.
func TestVaultCapabilityGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "sec@x", "password123", false)
	atok := adminToken(t, url)
	stok := authClient(t, url, "sec@x", "password123")

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	vc := vaultv1connect.NewVaultServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Two folders, one asset each (admin setup).
	fA, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "fa-" + uuid.NewString()}), atok))
	if err != nil {
		t.Fatalf("create folder A: %v", err)
	}
	assetA, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fA.Msg.Folder.Id, Name: "a", Kind: "ssh"}), atok))
	if err != nil {
		t.Fatalf("create asset A: %v", err)
	}
	fB, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "fb-" + uuid.NewString()}), atok))
	if err != nil {
		t.Fatalf("create folder B: %v", err)
	}
	assetB, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fB.Msg.Folder.Id, Name: "b", Kind: "ssh"}), atok))
	if err != nil {
		t.Fatalf("create asset B: %v", err)
	}

	// sec holds vault:secret:write bound at folder A → cascades to asset A.
	folderAID := uuid.MustParse(fA.Msg.Folder.Id)
	bindScopedCap(t, pool, userIDByEmail(t, pool, "sec@x"), `["vault:secret:write"]`, folderAID, uuid.Nil)

	// Allowed on A.
	if _, err := vc.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: assetA.Msg.Asset.Id, Name: "pw", Value: []byte("x")}), stok)); err != nil {
		t.Fatalf("sec SetAssetSecret on A = %v, want ok", err)
	}
	// Denied on B (out of scope).
	if _, err := vc.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: assetB.Msg.Asset.Id, Name: "pw", Value: []byte("x")}), stok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("sec SetAssetSecret on B = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// Denied on InitCA (needs vault:ca:init global).
	if _, err := vc.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), stok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("sec InitCA = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Admin (**) can do all.
	if _, err := vc.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: assetB.Msg.Asset.Id, Name: "pw2", Value: []byte("y")}), atok)); err != nil {
		t.Fatalf("admin SetAssetSecret on B = %v, want ok", err)
	}
	if _, err := vc.InitCA(ctx, withToken(connect.NewRequest(&vaultv1.InitCARequest{Kind: "ssh"}), atok)); err != nil {
		t.Fatalf("admin InitCA = %v, want ok", err)
	}
}
