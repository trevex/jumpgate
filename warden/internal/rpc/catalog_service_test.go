package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// seedAssetSecret inserts an asset_secrets row directly (a dummy sealed blob is
// fine — the catalog service never opens it) and returns the secret id.
func seedAssetSecret(t *testing.T, pool *pgxpool.Pool, assetID, name string) string {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO asset_secrets (asset_id, name, sealed) VALUES ($1, $2, $3) RETURNING id`,
		assetID, name, []byte("sealed")).Scan(&id); err != nil {
		t.Fatalf("seed asset secret: %v", err)
	}
	return id.String()
}

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
// with inline ca logins returns the config and GetAsset reads them back.
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
			TargetAddress: "10.0.0.9:22",
			Logins: []*catalogv1.SSHLogin{
				{Login: "root", Kind: "ca"},
				{Login: "deploy", Kind: "ca"},
			},
		}},
	}), tok))
	if err != nil {
		t.Fatalf("create asset with config: %v", err)
	}
	if s := created.Msg.Asset.GetSsh(); s == nil || len(s.GetLogins()) != 2 {
		t.Fatalf("create response config mismatch: %+v", created.Msg.Asset)
	}

	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: created.Msg.Asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	s := got.Msg.Asset.GetSsh()
	if s == nil || s.TargetAddress != "10.0.0.9:22" || len(s.GetLogins()) != 2 {
		t.Fatalf("GetAsset config mismatch: %+v", got.Msg.Asset)
	}
	// Logins are returned ordered by login name: deploy, root.
	byLogin := map[string]*catalogv1.SSHLogin{}
	for _, l := range s.GetLogins() {
		byLogin[l.GetLogin()] = l
	}
	if byLogin["root"] == nil || byLogin["root"].GetKind() != "ca" || byLogin["root"].GetSecretId() != "" {
		t.Fatalf("root login mismatch: %+v", s.GetLogins())
	}
	if byLogin["deploy"] == nil || byLogin["deploy"].GetKind() != "ca" {
		t.Fatalf("deploy login mismatch: %+v", s.GetLogins())
	}
}

// TestCatalogCreateAssetConfigRollsBack asserts CreateAsset with a bad inline
// config (a password login without a secret violates the CHECK) rolls back the
// asset — no orphan.
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
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfig{
			Logins: []*catalogv1.SSHLogin{{Login: "root", Kind: "password"}},
		}},
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

// TestCatalogUpdateAssetConfigPasswordLogin covers adding a password login after a
// secret is seeded: the login round-trips (carrying its secret_id), while a
// password login with an empty secret_id is rejected by the CHECK.
func TestCatalogUpdateAssetConfigPasswordLogin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	secretID := seedAssetSecret(t, pool, asset.Id, "demo")

	upd := func(ssh *catalogv1.SSHConfig) error {
		_, err := c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
			AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: ssh},
		}), tok))
		return err
	}

	// A password login bound to the same-asset secret round-trips.
	if err := upd(&catalogv1.SSHConfig{
		TargetAddress: "10.0.0.9:22",
		Logins:        []*catalogv1.SSHLogin{{Login: "demo", Kind: "password", SecretId: secretID}},
	}); err != nil {
		t.Fatalf("update with password login: %v", err)
	}
	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	s := got.Msg.Asset.GetSsh()
	if s == nil || len(s.GetLogins()) != 1 {
		t.Fatalf("expected one login, got %+v", got.Msg.Asset)
	}
	if l := s.GetLogins()[0]; l.GetLogin() != "demo" || l.GetKind() != "password" || l.GetSecretId() != secretID {
		t.Fatalf("password login mismatch: %+v", l)
	}

	// A password login with no secret violates the ssh_login_secret_present CHECK.
	if connect.CodeOf(upd(&catalogv1.SSHConfig{
		TargetAddress: "10.0.0.9:22",
		Logins:        []*catalogv1.SSHLogin{{Login: "demo", Kind: "password"}},
	})) != connect.CodeInvalidArgument {
		t.Fatal("password login without a secret not rejected InvalidArgument")
	}
}

// TestCatalogUpdateAssetConfigForeignSecret asserts a login on asset A that
// references asset B's secret is rejected by the composite FK.
func TestCatalogUpdateAssetConfigForeignSecret(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	assetA := newAsset(t, url, tok, "ssh")
	assetB := newAsset(t, url, tok, "ssh")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// The secret belongs to asset B.
	foreignSecret := seedAssetSecret(t, pool, assetB.Id, "demo")

	_, err := c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetA.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfig{
			TargetAddress: "10.0.0.9:22",
			Logins:        []*catalogv1.SSHLogin{{Login: "demo", Kind: "password", SecretId: foreignSecret}},
		}},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("cross-asset secret_id = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// TestCatalogUpdateAssetConfig covers UpdateAssetConfig upsert + the optional
// host_public_key contract (valid round-trips, empty clears, garbage rejected).
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

	if err := upd(&catalogv1.SSHConfig{
		Logins:        []*catalogv1.SSHLogin{{Login: "root", Kind: "ca"}},
		HostPublicKey: hostKey, TargetAddress: "10.0.0.9:22",
	}); err != nil {
		t.Fatalf("update with host key: %v", err)
	}
	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if s := got.Msg.Asset.GetSsh(); s == nil || s.HostPublicKey != hostKey || s.TargetAddress != "10.0.0.9:22" || len(s.GetLogins()) != 1 {
		t.Fatalf("roundtrip mismatch: %+v", got.Msg.Asset)
	}

	// Clearing host/target and replacing the login set.
	if err := upd(&catalogv1.SSHConfig{Logins: []*catalogv1.SSHLogin{{Login: "root", Kind: "ca"}}}); err != nil {
		t.Fatalf("update clear: %v", err)
	}
	got2, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset (post-clear): %v", err)
	}
	if s := got2.Msg.Asset.GetSsh(); s == nil || s.HostPublicKey != "" || s.TargetAddress != "" {
		t.Fatalf("not cleared: %+v", got2.Msg.Asset)
	}

	if connect.CodeOf(upd(&catalogv1.SSHConfig{
		Logins:        []*catalogv1.SSHLogin{{Login: "root", Kind: "ca"}},
		HostPublicKey: "not a key",
	})) != connect.CodeInvalidArgument {
		t.Fatal("bad host key not rejected InvalidArgument")
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

func TestCreateFolderSiblingUniqueness(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()
	mk := func(name, parent string) error {
		req := &catalogv1.CreateFolderRequest{Name: name}
		if parent != "" {
			req.ParentId = parent
		}
		_, err := c.CreateFolder(ctx, withToken(connect.NewRequest(req), tok))
		return err
	}

	if err := mk("prod", ""); err != nil {
		t.Fatalf("first top-level: %v", err)
	}
	if err := mk("prod", ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup top-level = %v, want AlreadyExists", connect.CodeOf(err))
	}
	// case-folded: 'PROD' collides with 'prod'
	if err := mk("PROD", ""); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("case-folded dup = %v, want AlreadyExists", connect.CodeOf(err))
	}
	// same name under a different parent is fine
	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db"}), tok))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	if f.Msg.Folder.Path != "db" {
		t.Fatalf("top-level folder path = %q, want %q", f.Msg.Folder.Path, "db")
	}
	child, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod", ParentId: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("prod under db should be allowed: %v", err)
	}
	if child.Msg.Folder.Path != "prod.db" {
		t.Fatalf("child folder path = %q, want %q", child.Msg.Folder.Path, "prod.db")
	}
}

func TestCreateAssetSiblingUniqueness(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	fid := f.Msg.Folder.Id
	mkAsset := func(name string) error {
		_, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fid, Name: name}), tok))
		return err
	}

	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fid, Name: "web"}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if a.Msg.Asset.Path != "web.prod" {
		t.Fatalf("asset path = %q, want %q", a.Msg.Asset.Path, "web.prod")
	}
	// duplicate asset name in the same folder
	if err := mkAsset("web"); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup asset = %v, want AlreadyExists", connect.CodeOf(err))
	}
	// case-folded collision
	if err := mkAsset("WEB"); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("case-folded asset = %v, want AlreadyExists", connect.CodeOf(err))
	}
	// cross-table: a subfolder named 'web' under prod collides with the asset 'web'
	if _, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "web", ParentId: fid}), tok)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("folder colliding with sibling asset = %v, want AlreadyExists", connect.CodeOf(err))
	}
	// reverse cross-table: create a subfolder 'api' under prod, then an asset 'api'
	// under prod must collide with it.
	if _, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "api", ParentId: fid}), tok)); err != nil {
		t.Fatalf("create subfolder api: %v", err)
	}
	if err := mkAsset("api"); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("asset colliding with sibling folder = %v, want AlreadyExists", connect.CodeOf(err))
	}
}

func TestCatalogReadsPopulatePath(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	prod, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("prod: %v", err)
	}
	db, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db", ParentId: prod.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: db.Msg.Folder.Id, Name: "pg-primary"}), tok))
	if err != nil {
		t.Fatalf("asset: %v", err)
	}

	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: a.Msg.Asset.Id}), tok))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Msg.Asset.Path != "pg-primary.db.prod" {
		t.Fatalf("GetAsset path = %q, want pg-primary.db.prod", got.Msg.Asset.Path)
	}

	list, err := c.ListAssetsByFolder(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsByFolderRequest{FolderId: db.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(list.Msg.Assets) != 1 || list.Msg.Assets[0].Path != "pg-primary.db.prod" {
		t.Fatalf("ListAssetsByFolder path = %v, want pg-primary.db.prod", list.Msg.Assets)
	}

	folders, err := c.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 100}), tok))
	if err != nil {
		t.Fatalf("list folders: %v", err)
	}
	paths := map[string]string{}
	for _, f := range folders.Msg.Folders {
		paths[f.Id] = f.Path
	}
	if paths[db.Msg.Folder.Id] != "db.prod" {
		t.Fatalf("ListFolders path for db = %q, want db.prod", paths[db.Msg.Folder.Id])
	}
}

func TestCreateFolderAssetRaceSingleWinner(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	parent, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	pid := parent.Msg.Folder.Id

	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		_, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "web", ParentId: pid}), tok))
		errs <- err
	}()
	go func() {
		<-start
		_, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: pid, Name: "web"}), tok))
		errs <- err
	}()
	close(start)

	var ok, already int
	for i := 0; i < 2; i++ {
		err := <-errs
		switch {
		case err == nil:
			ok++
		case connect.CodeOf(err) == connect.CodeAlreadyExists:
			already++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || already != 1 {
		t.Fatalf("race result ok=%d already=%d, want exactly 1 and 1", ok, already)
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
		AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfig{
			Logins: []*catalogv1.SSHLogin{{Login: "root", Kind: "ca"}},
		}},
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin UpdateAssetConfig = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// giveAssetAccess grants the user (looked up by email) a standing role with
// ssh:login:* on the given asset, seeded directly via DB queries. This mirrors
// the authz-seeding pattern used by the m4a e2e and authz unit tests.
func giveAssetAccess(t *testing.T, pool *pgxpool.Pool, email, assetID string) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	u, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("giveAssetAccess: GetUserByEmail(%s): %v", email, err)
	}
	aid, err := uuid.Parse(assetID)
	if err != nil {
		t.Fatalf("giveAssetAccess: parse assetID %s: %v", assetID, err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name:         "resolve-test-" + uuid.NewString(),
		ResourceType: "asset",
		Capabilities: []byte(`["ssh:login:*"]`),
	})
	if err != nil {
		t.Fatalf("giveAssetAccess: CreateRole: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeAssetID:  pgtype.UUID{Bytes: aid, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatalf("giveAssetAccess: CreateRoleBinding: %v", err)
	}
}

func TestResolveFolder(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	prod, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil { t.Fatalf("prod: %v", err) }
	db, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db", ParentId: prod.Msg.Folder.Id}), tok))
	if err != nil { t.Fatalf("db: %v", err) }

	got, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "db.prod"}), tok))
	if err != nil { t.Fatalf("resolve db.prod: %v", err) }
	if got.Msg.FolderId != db.Msg.Folder.Id || got.Msg.Path != "db.prod" {
		t.Fatalf("resolve db.prod = {%s,%s}, want {%s, db.prod}", got.Msg.FolderId, got.Msg.Path, db.Msg.Folder.Id)
	}
	gotTop, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "prod"}), tok))
	if err != nil || gotTop.Msg.FolderId != prod.Msg.Folder.Id || gotTop.Msg.Path != "prod" {
		t.Fatalf("resolve prod = %v / {%s,%s}", err, gotTop.Msg.GetFolderId(), gotTop.Msg.GetPath())
	}
	gotID, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: db.Msg.Folder.Id}), tok))
	if err != nil || gotID.Msg.Path != "db.prod" {
		t.Fatalf("resolve uuid = %v / %q", err, gotID.Msg.GetPath())
	}
	if _, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "nope.prod"}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("bad path = %v, want NotFound", connect.CodeOf(err))
	}
	seedUser(t, pool, "u@x", "password123", false)
	utok := authClient(t, url, "u@x", "password123")
	if _, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "prod"}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestResolveAsset(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	prod, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("prod: %v", err)
	}
	db, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db", ParentId: prod.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: db.Msg.Folder.Id, Name: "pg", Kind: "ssh"}), tok))
	if err != nil {
		t.Fatalf("asset: %v", err)
	}

	// A non-admin user WITH access to the asset (role w/ ssh:login:* + standing binding).
	seedUser(t, pool, "u@x", "password123", false)
	utok := authClient(t, url, "u@x", "password123")
	giveAssetAccess(t, pool, "u@x", a.Msg.Asset.Id)
	uc := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)

	// path ref resolves for the entitled user → canonical DNS path
	got, err := uc.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "pg.db.prod"}), utok))
	if err != nil {
		t.Fatalf("resolve path: %v", err)
	}
	if got.Msg.AssetId != a.Msg.Asset.Id || got.Msg.Path != "pg.db.prod" {
		t.Fatalf("resolve = {%s,%s}, want {%s, pg.db.prod}", got.Msg.AssetId, got.Msg.Path, a.Msg.Asset.Id)
	}
	// uuid ref round-trips to the canonical path
	gotID, err := uc.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: a.Msg.Asset.Id}), utok))
	if err != nil || gotID.Msg.Path != "pg.db.prod" {
		t.Fatalf("resolve uuid = %v / path=%q", err, gotID.Msg.GetPath())
	}
	// a user with NO access → NotFound (indistinguishable from absent)
	seedUser(t, pool, "no@x", "password123", false)
	notok := authClient(t, url, "no@x", "password123")
	if _, err := uc.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "pg.db.prod"}), notok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("no-access = %v, want NotFound", connect.CodeOf(err))
	}
	// a wrong path → NotFound even for the entitled user
	if _, err := uc.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "nope.db.prod"}), utok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("bad path = %v, want NotFound", connect.CodeOf(err))
	}
}
