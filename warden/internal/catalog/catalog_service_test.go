package catalog_test

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
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: "pg-prod", Config: emptySSHConfig()}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assets, err := c.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: f.Msg.Folder.Id}), tok))
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
		FolderId: f.Msg.Folder.Id, Name: "box",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.9:22",
			Logins: []*catalogv1.SSHLoginInput{
				{Login: "root", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
				{Login: "deploy", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}},
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
// config (existing_secret_id is forbidden on create — a brand-new asset has no
// secrets) is rejected AFTER the asset row is inserted, and the whole tx rolls
// back — no orphan asset.
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
		FolderId: f.Msg.Folder.Id, Name: "orphan",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			Logins: []*catalogv1.SSHLoginInput{{Login: "root", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: uuid.NewString()}}}}},
		}},
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("create with bad config = %v, want InvalidArgument", connect.CodeOf(err))
	}
	list, err := c.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: f.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Msg.Assets) != 0 {
		t.Fatalf("create rolled back but %d asset(s) remain: %+v", len(list.Msg.Assets), list.Msg.Assets)
	}
}

// TestCatalogUpdateAssetConfigPasswordLogin covers a password login on
// UpdateAssetConfig: an inline new_value seals a fresh secret (the login round-trips
// carrying a non-empty secret_id), and an existing_secret_id belonging to the asset
// is accepted (the login round-trips carrying that same secret_id).
func TestCatalogUpdateAssetConfigPasswordLogin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	asset := newAsset(t, url, tok, "ssh")
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	upd := func(ssh *catalogv1.SSHConfigInput) error {
		_, err := c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
			AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: ssh},
		}), tok))
		return err
	}

	// A password login with an inline new_value seals a fresh secret and round-trips.
	if err := upd(&catalogv1.SSHConfigInput{
		TargetAddress: "10.0.0.9:22",
		Logins: []*catalogv1.SSHLoginInput{{Login: "demo", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_NewValue{NewValue: []byte("s3cr3t")}}}}},
	}); err != nil {
		t.Fatalf("update with inline password login: %v", err)
	}
	got, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	s := got.Msg.Asset.GetSsh()
	if s == nil || len(s.GetLogins()) != 1 {
		t.Fatalf("expected one login, got %+v", got.Msg.Asset)
	}
	sealed := s.GetLogins()[0]
	if sealed.GetLogin() != "demo" || sealed.GetKind() != "password" || sealed.GetSecretId() == "" {
		t.Fatalf("sealed password login mismatch: %+v", sealed)
	}

	// Re-using that same secret via existing_secret_id round-trips to the same id.
	if err := upd(&catalogv1.SSHConfigInput{
		TargetAddress: "10.0.0.9:22",
		Logins: []*catalogv1.SSHLoginInput{{Login: "demo", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: sealed.GetSecretId()}}}}},
	}); err != nil {
		t.Fatalf("update with existing_secret_id: %v", err)
	}
	got2, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset (existing): %v", err)
	}
	if l := got2.Msg.Asset.GetSsh().GetLogins()[0]; l.GetSecretId() != sealed.GetSecretId() {
		t.Fatalf("existing_secret_id login = %+v, want secret_id %s", l, sealed.GetSecretId())
	}
}

// TestCatalogUpdateAssetConfigForeignSecret asserts a login on asset A that
// references asset B's secret via existing_secret_id is rejected (same-asset check).
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
		AssetId: assetA.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.9:22",
			Logins: []*catalogv1.SSHLoginInput{{Login: "demo", Auth: &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
				Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: foreignSecret}}}}},
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

	caLogin := func() []*catalogv1.SSHLoginInput {
		return []*catalogv1.SSHLoginInput{{Login: "root", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}}}
	}
	upd := func(ssh *catalogv1.SSHConfigInput) error {
		_, err := c.UpdateAssetConfig(ctx, withToken(connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
			AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: ssh},
		}), tok))
		return err
	}

	if err := upd(&catalogv1.SSHConfigInput{
		Logins:        caLogin(),
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
	if err := upd(&catalogv1.SSHConfigInput{Logins: caLogin()}); err != nil {
		t.Fatalf("update clear: %v", err)
	}
	got2, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: asset.Id}), tok))
	if err != nil {
		t.Fatalf("GetAsset (post-clear): %v", err)
	}
	if s := got2.Msg.Asset.GetSsh(); s == nil || s.HostPublicKey != "" || s.TargetAddress != "" {
		t.Fatalf("not cleared: %+v", got2.Msg.Asset)
	}

	if connect.CodeOf(upd(&catalogv1.SSHConfigInput{
		Logins:        caLogin(),
		HostPublicKey: "not a key",
	})) != connect.CodeInvalidArgument {
		t.Fatal("bad host key not rejected InvalidArgument")
	}
}

// TestCatalogGetAsset covers an asset onboarded with an empty SSH config (a config
// row exists but carries no logins/target) and an unknown asset (NotFound). Every
// asset now has a config row since the config oneof is required at create.
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
	if s := got.Msg.Asset.GetSsh(); s == nil || len(s.GetLogins()) != 0 || s.GetTargetAddress() != "" {
		t.Fatalf("expected empty ssh config, got %+v", got.Msg.Asset.GetSsh())
	}
	_, err = c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: "11111111-1111-1111-1111-111111111111"}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("GetAsset unknown = %v, want NotFound", connect.CodeOf(err))
	}
}

// fakeReqReads is a controllable requestReadAuthorizer for GetAssetDisplay tests.
type fakeReqReads struct {
	allow bool
	err   error
}

func (f fakeReqReads) CanReadForRequest(_ context.Context, _ uuid.UUID, _ accessrequest.ReqEntityKind, _ uuid.UUID) (bool, error) {
	return f.allow, f.err
}

// userID returns the id of a previously seeded user by email.
func userID(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email=$1`, email).Scan(&id); err != nil {
		t.Fatalf("lookup user %q: %v", email, err)
	}
	return id
}

// TestGetAssetDisplay exercises the display handler directly with a controllable
// request-party authorizer: a request-party (no cap) is served, a cap-holder is
// served, a caller with neither is NotFound, and a missing id is NotFound. The
// SSH decision context (target address + logins) is present and carries no secret
// reference (SSHLoginDisplay has no such field).
func TestGetAssetDisplay(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true) // holds ** → catalog:asset:read
	tok := adminToken(t, url)

	// Onboard an SSH asset with a target address + a ca login, over the wire.
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()
	folderName := "f-" + uuid.New().String()
	f, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: folderName}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: f.Msg.Folder.Id, Name: "pg-primary",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			TargetAddress: "10.0.0.5:22",
			Logins:        []*catalogv1.SSHLoginInput{{Login: "root", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}}},
		}},
	}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assetID := uuid.MustParse(a.Msg.Asset.Id)

	// Seed a capless user (party candidate) and a cap-holder.
	seedUser(t, pool, "party@x", "password123", false) // no caps
	seedUser(t, pool, "capper@x", "password123", true) // holds ** → cap path
	party := auth.CurrentUser{ID: userID(t, pool, "party@x"), Email: "party@x"}
	capper := auth.CurrentUser{ID: userID(t, pool, "capper@x"), Email: "capper@x"}

	authorizer := authz.New(pool)
	q := sqlc.New(pool)

	// A server whose fake authorizes the request-party path.
	allowSrv := catalog.NewHandler(catalog.NewService(pool, testSealer(t), nil, authorizer, fakeReqReads{allow: true}), apiguard.New(authorizer, q))
	// A server whose fake denies the request-party path (only the cap path can pass).
	denySrv := catalog.NewHandler(catalog.NewService(pool, testSealer(t), nil, authorizer, fakeReqReads{allow: false}), apiguard.New(authorizer, q))

	assertSSH := func(t *testing.T, resp *catalogv1.GetAssetDisplayResponse) {
		t.Helper()
		d := resp.GetAsset()
		if d.GetPath() != "pg-primary."+folderName {
			t.Fatalf("path = %q, want %q", d.GetPath(), "pg-primary."+folderName)
		}
		if d.GetKind() != "ssh" {
			t.Fatalf("kind = %q, want ssh", d.GetKind())
		}
		ssh := d.GetSsh()
		if ssh == nil {
			t.Fatalf("expected ssh config, got %+v", d.GetConfig())
		}
		if ssh.GetTargetAddress() != "10.0.0.5:22" {
			t.Fatalf("target_address = %q, want 10.0.0.5:22", ssh.GetTargetAddress())
		}
		if len(ssh.GetLogins()) != 1 || ssh.GetLogins()[0].GetLogin() != "root" || ssh.GetLogins()[0].GetKind() != "ca" {
			t.Fatalf("logins = %+v, want [root/ca]", ssh.GetLogins())
		}
	}

	// (1) request-party, NO cap → served.
	partyCtx := auth.WithUser(ctx, party)
	got, err := allowSrv.GetAssetDisplay(partyCtx, connect.NewRequest(&catalogv1.GetAssetDisplayRequest{AssetId: assetID.String()}))
	if err != nil {
		t.Fatalf("party GetAssetDisplay: %v", err)
	}
	assertSSH(t, got.Msg)

	// (2) cap-holder (fake denies) → served via the cap path.
	capCtx := auth.WithUser(ctx, capper)
	got, err = denySrv.GetAssetDisplay(capCtx, connect.NewRequest(&catalogv1.GetAssetDisplayRequest{AssetId: assetID.String()}))
	if err != nil {
		t.Fatalf("cap GetAssetDisplay: %v", err)
	}
	assertSSH(t, got.Msg)

	// (3) neither cap nor request-party → NotFound (topology hiding).
	_, err = denySrv.GetAssetDisplay(partyCtx, connect.NewRequest(&catalogv1.GetAssetDisplayRequest{AssetId: assetID.String()}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unauthorized display = %v, want NotFound", connect.CodeOf(err))
	}

	// (4) missing asset id (well-formed but absent) → NotFound, even for the cap holder.
	_, err = allowSrv.GetAssetDisplay(capCtx, connect.NewRequest(&catalogv1.GetAssetDisplayRequest{AssetId: "11111111-1111-1111-1111-111111111111"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing display = %v, want NotFound", connect.CodeOf(err))
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
		_, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fid, Name: name, Config: emptySSHConfig()}), tok))
		return err
	}

	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: fid, Name: "web", Config: emptySSHConfig()}), tok))
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
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: db.Msg.Folder.Id, Name: "pg-primary", Config: emptySSHConfig()}), tok))
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

	list, err := c.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: db.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(list.Msg.Assets) != 1 || list.Msg.Assets[0].Path != "pg-primary.db.prod" {
		t.Fatalf("ListAssets path = %v, want pg-primary.db.prod", list.Msg.Assets)
	}

	// db is nested under prod, so cascade from root to reach it and verify its path.
	folders, err := c.ListFolders(ctx, withToken(connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 100, Cascade: true}), tok))
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
		_, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: pid, Name: "web", Config: emptySSHConfig()}), tok))
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
		AssetId: asset.Id, Config: &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
			Logins: []*catalogv1.SSHLoginInput{{Login: "root", Auth: &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}}},
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
	q := sqlc.New(pool)

	u, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("giveAssetAccess: GetUserByEmail(%s): %v", email, err)
	}
	aid, err := uuid.Parse(assetID)
	if err != nil {
		t.Fatalf("giveAssetAccess: parse assetID %s: %v", assetID, err)
	}
	role := createRoleWithCaps(t, ctx, q, "resolve-test-"+uuid.NewString(), pgtype.UUID{}, `["ssh:login:*"]`)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeAssetID:  pgtype.UUID{Bytes: aid, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatalf("giveAssetAccess: CreateRoleBinding: %v", err)
	}
}

// TestCatalogCapabilityGating asserts the catalog handlers are gated by
// scoped management capabilities (not a blanket admin check): dana, bound the
// folder-editor role (catalog:asset:create/read) at folder `team`, can create
// and read assets under team but not under its parent `demo`, and cannot create
// folders; the bootstrap admin (**) can do everything.
func TestCatalogCapabilityGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Setup as the bootstrap admin: demo/ and team/ under demo.
	demo, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "demo"}), tok))
	if err != nil {
		t.Fatalf("create demo: %v", err)
	}
	team, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "team", ParentId: demo.Msg.Folder.Id}), tok))
	if err != nil {
		t.Fatalf("create team: %v", err)
	}

	// A non-admin user dana holding folder-editor bound at folder team.
	seedUser(t, pool, "dana@x", "password123", false)
	danatok := authClient(t, url, "dana@x", "password123")

	q := sqlc.New(pool)
	teamID, err := uuid.Parse(team.Msg.Folder.Id)
	if err != nil {
		t.Fatalf("parse team id: %v", err)
	}
	role := createRoleWithCaps(t, ctx, q, "folder-editor", pgtype.UUID{}, `["catalog:asset:create","catalog:asset:read"]`)
	// A folder-scoped binding on `team` confers management authority that CASCADES
	// structurally down the folder tree (CapabilitiesOnScope walks the folder
	// ancestor chain), so dana can read (AssetScope) the child assets she creates
	// under team WITHOUT any via='parent' self-grant.
	dana, err := q.GetUserByEmail(ctx, "dana@x")
	if err != nil {
		t.Fatalf("get dana: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeFolderID: pgtype.UUID{Bytes: teamID, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: dana.ID, Valid: true},
	}); err != nil {
		t.Fatalf("bind role: %v", err)
	}

	// dana CAN create an asset under team (holds catalog:asset:create on team).
	danaAsset, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: team.Msg.Folder.Id, Name: "box", Config: emptySSHConfig()}), danatok))
	if err != nil {
		t.Fatalf("dana CreateAsset under team: %v", err)
	}
	// dana CAN read it back (holds catalog:asset:read on team → asset scope).
	if _, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: danaAsset.Msg.Asset.Id}), danatok)); err != nil {
		t.Fatalf("dana GetAsset: %v", err)
	}

	// dana CANNOT create an asset under demo (the parent — she only holds it on team).
	if _, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: demo.Msg.Folder.Id, Name: "nope", Config: emptySSHConfig()}), danatok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana CreateAsset under demo = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// dana CANNOT create a folder (no catalog:folder:create anywhere).
	if _, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "sub", ParentId: team.Msg.Folder.Id}), danatok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("dana CreateFolder = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// The admin (**) CAN do all of the above.
	adminAsset, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: demo.Msg.Folder.Id, Name: "admin-box", Config: emptySSHConfig()}), tok))
	if err != nil {
		t.Fatalf("admin CreateAsset under demo: %v", err)
	}
	if _, err := c.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: adminAsset.Msg.Asset.Id}), tok)); err != nil {
		t.Fatalf("admin GetAsset: %v", err)
	}
	if _, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "admin-sub", ParentId: team.Msg.Folder.Id}), tok)); err != nil {
		t.Fatalf("admin CreateFolder: %v", err)
	}
}

// TestSearchCatalog covers the visibility-filtered catalog search: a substring
// query returns only the caller's VISIBLE matching entities across multiple kinds,
// an entity the caller cannot see never appears (existence hiding), the limit is
// respected, and the match is case-insensitive.
func TestSearchCatalog(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	q := sqlc.New(pool)

	// Two sibling top-level folders. The caller will hold management read on `vis`
	// (which cascades down the tree) and NOTHING on `hidden`.
	visF, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "pgvis"}), tok))
	if err != nil {
		t.Fatalf("create vis folder: %v", err)
	}
	hiddenF, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "hidden"}), tok))
	if err != nil {
		t.Fatalf("create hidden folder: %v", err)
	}
	visFID := uuid.MustParse(visF.Msg.Folder.Id)
	hiddenFID := uuid.MustParse(hiddenF.Msg.Folder.Id)

	// Under vis: an asset, a role, and a group whose names all share "pg". Plus a
	// child folder named with "pg" so folder hits are covered too.
	if _, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: visF.Msg.Folder.Id, Name: "pg-primary", Config: emptySSHConfig(),
	}), tok)); err != nil {
		t.Fatalf("create vis asset: %v", err)
	}
	if _, err := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{
		Name: "pg-child", ParentId: visF.Msg.Folder.Id,
	}), tok)); err != nil {
		t.Fatalf("create vis child folder: %v", err)
	}
	createRoleWithCaps(t, ctx, q, "pg-operator", pgtype.UUID{Bytes: visFID, Valid: true}, "[]")
	if _, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{
		Name:     "pg-team",
		FolderID: pgtype.UUID{Bytes: visFID, Valid: true},
	}); err != nil {
		t.Fatalf("create vis group: %v", err)
	}

	// Under hidden: an asset the caller must NEVER see, whose name also matches "pg".
	if _, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: hiddenF.Msg.Folder.Id, Name: "pg-secret", Config: emptySSHConfig(),
	}), tok)); err != nil {
		t.Fatalf("create hidden asset: %v", err)
	}
	createRoleWithCaps(t, ctx, q, "pg-secret-role", pgtype.UUID{Bytes: hiddenFID, Valid: true}, "[]")

	// A non-admin caller who holds management read on the vis folder only. Those
	// caps cascade down the vis subtree, making its folders/assets/roles/groups
	// visible while leaving the hidden sibling invisible.
	seedUser(t, pool, "searcher@x", "password123", false)
	su, err := q.GetUserByEmail(ctx, "searcher@x")
	if err != nil {
		t.Fatalf("get searcher: %v", err)
	}
	role := createRoleWithCaps(t, ctx, q, "vis-reader", pgtype.UUID{}, `["catalog:folder:read","catalog:asset:read","access:role:read","identity:group:read"]`)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeFolderID: pgtype.UUID{Bytes: visFID, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: su.ID, Valid: true},
	}); err != nil {
		t.Fatalf("bind reader role: %v", err)
	}

	authorizer := authz.New(pool)
	srv := catalog.NewHandler(catalog.NewService(pool, testSealer(t), nil, authorizer, nil), apiguard.New(authorizer, q))
	searcherCtx := auth.WithUser(ctx, auth.CurrentUser{ID: su.ID, Email: "searcher@x"})

	// (a) substring "pg" returns the caller's visible matches across multiple kinds.
	resp, err := srv.SearchCatalog(searcherCtx, connect.NewRequest(&catalogv1.SearchCatalogRequest{Query: "pg"}))
	if err != nil {
		t.Fatalf("SearchCatalog: %v", err)
	}
	byKind := map[string]map[string]bool{}
	for _, h := range resp.Msg.GetHits() {
		if byKind[h.GetKind()] == nil {
			byKind[h.GetKind()] = map[string]bool{}
		}
		byKind[h.GetKind()][h.GetName()] = true
	}
	if !byKind["asset"]["pg-primary"] {
		t.Fatalf("missing visible asset pg-primary: %+v", resp.Msg.GetHits())
	}
	if !byKind["folder"]["pg-child"] {
		t.Fatalf("missing visible folder pg-child: %+v", resp.Msg.GetHits())
	}
	if !byKind["role"]["pg-operator"] {
		t.Fatalf("missing visible role pg-operator: %+v", resp.Msg.GetHits())
	}
	if !byKind["group"]["pg-team"] {
		t.Fatalf("missing visible group pg-team: %+v", resp.Msg.GetHits())
	}

	// (b) hidden entities never appear (existence hiding).
	for _, h := range resp.Msg.GetHits() {
		if h.GetName() == "pg-secret" || h.GetName() == "pg-secret-role" {
			t.Fatalf("hidden entity leaked: %+v", h)
		}
	}

	// (c) limit is respected: 4+ visible matches, cap at 2.
	limited, err := srv.SearchCatalog(searcherCtx, connect.NewRequest(&catalogv1.SearchCatalogRequest{Query: "pg", Limit: 2}))
	if err != nil {
		t.Fatalf("SearchCatalog limited: %v", err)
	}
	if len(limited.Msg.GetHits()) > 2 {
		t.Fatalf("limit not respected: got %d hits", len(limited.Msg.GetHits()))
	}

	// (d) case-insensitive: "PG" matches "pg-*".
	upper, err := srv.SearchCatalog(searcherCtx, connect.NewRequest(&catalogv1.SearchCatalogRequest{Query: "PG"}))
	if err != nil {
		t.Fatalf("SearchCatalog upper: %v", err)
	}
	var sawPrimary bool
	for _, h := range upper.Msg.GetHits() {
		if h.GetName() == "pg-primary" {
			sawPrimary = true
		}
		if h.GetName() == "pg-secret" {
			t.Fatalf("hidden entity leaked (upper): %+v", h)
		}
	}
	if !sawPrimary {
		t.Fatalf("case-insensitive match failed: %+v", upper.Msg.GetHits())
	}
}

func TestResolveFolder(t *testing.T) {
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

	got, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "db.prod"}), tok))
	if err != nil {
		t.Fatalf("resolve db.prod: %v", err)
	}
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
	// A caller without catalog:folder:read gets NotFound for an EXISTING folder —
	// identical to the nonexistent-ref case above — so folder existence never leaks
	// (existence hiding, matching ResolveAsset). It must NOT be PermissionDenied,
	// which would distinguish "exists but hidden" from "does not exist".
	seedUser(t, pool, "u@x", "password123", false)
	utok := authClient(t, url, "u@x", "password123")
	if _, err := c.ResolveFolder(ctx, withToken(connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: "prod"}), utok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("non-admin existing folder = %v, want NotFound (existence hiding)", connect.CodeOf(err))
	}
}

func TestResolveAssetAdminBypassAndTargetedCheck(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	prod, _ := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	db, _ := c.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "db", ParentId: prod.Msg.Folder.Id}), tok))
	a, _ := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: db.Msg.Folder.Id, Name: "pg", Config: emptySSHConfig()}), tok))

	// ADMIN resolves the asset by path WITH NO grant (the key change).
	got, err := c.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "pg.db.prod"}), tok))
	if err != nil || got.Msg.AssetId != a.Msg.Asset.Id || got.Msg.Path != "pg.db.prod" {
		t.Fatalf("admin resolve = %v / {%s,%s}, want the asset", err, got.Msg.GetAssetId(), got.Msg.GetPath())
	}
	// non-admin with NO access → NotFound (targeted RolesOnAsset check)
	seedUser(t, pool, "no@x", "password123", false)
	notok := authClient(t, url, "no@x", "password123")
	if _, err := c.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "pg.db.prod"}), notok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("no-access = %v, want NotFound", connect.CodeOf(err))
	}
	// non-admin WITH a standing binding resolves it
	seedUser(t, pool, "y@x", "password123", false)
	ytok := authClient(t, url, "y@x", "password123")
	giveAssetAccess(t, pool, "y@x", a.Msg.Asset.Id)
	if _, err := c.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: "pg.db.prod"}), ytok)); err != nil {
		t.Fatalf("entitled user resolve: %v", err)
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
	a, err := c.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: db.Msg.Folder.Id, Name: "pg", Config: emptySSHConfig()}), tok))
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
	if got.Msg.Kind != "ssh" {
		t.Fatalf("resolve kind = %q, want ssh", got.Msg.Kind)
	}
	// uuid ref round-trips to the canonical path
	gotID, err := uc.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: a.Msg.Asset.Id}), utok))
	if err != nil || gotID.Msg.Path != "pg.db.prod" {
		t.Fatalf("resolve uuid = %v / path=%q", err, gotID.Msg.GetPath())
	}
	if gotID.Msg.Kind != "ssh" {
		t.Fatalf("resolve uuid kind = %q, want ssh", gotID.Msg.Kind)
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
