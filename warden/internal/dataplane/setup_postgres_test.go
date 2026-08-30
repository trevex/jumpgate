package dataplane_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// pgFixture is a wired postgres mint→redeem harness: a postgres asset, a shared
// minter/verifier ed25519 key across the SetupService and the session.Service,
// and both an active x509 CA and a sealer for secret-backed logins.
type pgFixture struct {
	pool     *pgxpool.Pool
	q        *sqlc.Queries
	sealer   *secrets.Sealer
	ctx      context.Context
	user     uuid.UUID
	asset    uuid.UUID
	setupSvc *dataplane.SetupService
	sessSvc  *session.Service
	minter   *sessiontoken.Minter
}

// newPGFixture seeds a postgres asset + user and wires the SetupService and
// session.Service over ONE ed25519 keypair (mint and verify must share it). It
// also installs an active x509 CA (harmless for the password test).
func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	// Active x509 CA for mtls issuance.
	keyDER, certPEM, err := ca.GenerateX509CA()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateCAKey(ctx, sqlc.CreateCAKeyParams{Kind: "x509", Sealed: sealed, PublicMaterial: certPEM}); err != nil {
		t.Fatal(err)
	}

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "postgres"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertPostgresAssetConfig(ctx, sqlc.UpsertPostgresAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "pg:5432", TargetServerCa: "", DefaultDatabase: "appdb",
	}); err != nil {
		t.Fatalf("UpsertPostgresAssetConfig: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minter := sessiontoken.NewMinter(priv)
	verifier := sessiontoken.NewVerifier(pub)

	broker := vault.NewBroker(pool, sealer, authz.New(pool), audit.New(pool))
	setupSvc := dataplane.NewSetupService(pool, verifier, authz.New(pool), broker, audit.New(pool), time.Hour)
	sessSvc := session.NewService(q, authz.New(pool), minter, "gw:443", "", false, time.Hour, dataplane.NewRegistry())

	return &pgFixture{
		pool: pool, q: q, sealer: sealer, ctx: ctx,
		user: user.ID, asset: asset.ID,
		setupSvc: setupSvc, sessSvc: sessSvc, minter: minter,
	}
}

// login upserts a postgres asset login of the given role/kind (optional secret).
func (f *pgFixture) login(t *testing.T, role, kind string, secret pgtype.UUID) {
	t.Helper()
	if _, err := f.q.UpsertPostgresAssetLogin(f.ctx, sqlc.UpsertPostgresAssetLoginParams{
		AssetID: f.asset, Role: role, Kind: kind, SecretID: secret,
	}); err != nil {
		t.Fatalf("UpsertPostgresAssetLogin %q/%q: %v", role, kind, err)
	}
}

// grantCap creates a role carrying cap and standing-binds it to the user on the asset.
func (f *pgFixture) grantCap(t *testing.T, name, capPat string) {
	t.Helper()
	role, err := createRoleCaps(f.ctx, f.q, name, capPat)
	if err != nil {
		t.Fatalf("createRoleCaps: %v", err)
	}
	if _, err := f.q.CreateRoleBinding(f.ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pg(f.asset), SubjectUserID: pg(f.user),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// sealSecret seals value as an asset secret and returns its id.
func sealSecret(t *testing.T, q *sqlc.Queries, sealer *secrets.Sealer, asset uuid.UUID, name string, value []byte) uuid.UUID {
	t.Helper()
	sealed, err := sealer.Seal(value)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := q.SetAssetSecret(context.Background(), sqlc.SetAssetSecretParams{AssetID: asset, Name: name, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return sec.ID
}

// liveSessionProtocol reads the protocol column of the given live session.
func (f *pgFixture) liveSessionProtocol(t *testing.T, sessionID string) string {
	t.Helper()
	var proto string
	if err := f.pool.QueryRow(f.ctx, `SELECT protocol FROM live_sessions WHERE id=$1`, sessionID).Scan(&proto); err != nil {
		t.Fatalf("query live_sessions protocol: %v", err)
	}
	return proto
}

// TestSetupPostgresMTLS drives the happy path for an mtls login: mint a postgres
// bearer ticket, redeem it, and assert an x509 credential + postgres live session.
func TestSetupPostgresMTLS(t *testing.T) {
	f := newPGFixture(t)
	f.login(t, "readonly", "mtls", pgtype.UUID{})
	f.grantCap(t, "db-ro", "db:login:readonly")

	created, err := f.sessSvc.CreatePostgresSession(f.ctx, f.user, f.asset, "readonly")
	if err != nil {
		t.Fatalf("CreatePostgresSession: %v", err)
	}

	res, err := f.setupSvc.Setup(f.ctx, created.Token, "worker-1", "readonly", nil, nil)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res.CredentialKind != "x509" {
		t.Fatalf("CredentialKind = %q, want x509", res.CredentialKind)
	}
	if len(res.X509Certificate) == 0 || len(res.X509PrivateKey) == 0 {
		t.Fatalf("x509 cert/key empty: cert=%d key=%d", len(res.X509Certificate), len(res.X509PrivateKey))
	}
	if res.TargetAddress != "pg:5432" {
		t.Fatalf("TargetAddress = %q, want pg:5432", res.TargetAddress)
	}
	if res.DefaultDatabase != "appdb" {
		t.Fatalf("DefaultDatabase = %q, want appdb", res.DefaultDatabase)
	}
	if res.Login != "readonly" {
		t.Fatalf("Login = %q, want readonly", res.Login)
	}
	if !res.RecordingRequired {
		t.Error("postgres setup: RecordingRequired = false, want true")
	}
	if !strings.HasPrefix(res.RecordingObjectKey, "recordings/postgres/") ||
		!strings.HasSuffix(res.RecordingObjectKey, ".ndjson") {
		t.Errorf("postgres setup: RecordingObjectKey = %q, want recordings/postgres/....ndjson", res.RecordingObjectKey)
	}
	if got := f.liveSessionProtocol(t, res.SessionID); got != "postgres" {
		t.Fatalf("live_sessions.protocol = %q, want postgres", got)
	}
}

// TestSetupPostgresPassword drives a password login: the sealed secret is handed
// back as a pg-password credential.
func TestSetupPostgresPassword(t *testing.T) {
	f := newPGFixture(t)
	secID := sealSecret(t, f.q, f.sealer, f.asset, "app", []byte("s3cr3t"))
	f.login(t, "app", "password", pgtype.UUID{Bytes: secID, Valid: true})
	f.grantCap(t, "db-app", "db:login:app")

	created, err := f.sessSvc.CreatePostgresSession(f.ctx, f.user, f.asset, "app")
	if err != nil {
		t.Fatalf("CreatePostgresSession: %v", err)
	}

	res, err := f.setupSvc.Setup(f.ctx, created.Token, "worker-1", "app", nil, nil)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res.CredentialKind != "pg-password" {
		t.Fatalf("CredentialKind = %q, want pg-password", res.CredentialKind)
	}
	if res.Password != "s3cr3t" {
		t.Fatalf("Password = %q, want s3cr3t", res.Password)
	}
	if res.Login != "app" {
		t.Fatalf("Login = %q, want app", res.Login)
	}
	if got := f.liveSessionProtocol(t, res.SessionID); got != "postgres" {
		t.Fatalf("live_sessions.protocol = %q, want postgres", got)
	}
}

// TestSetupPostgresUnentitled asserts the db:login gate on both sides: the user
// holds db:login:writer, not the requested readonly, so the mint is refused
// (ErrNoAccess) and a raw-minted readonly ticket is refused at Setup (ErrNotAuthorized).
func TestSetupPostgresUnentitled(t *testing.T) {
	f := newPGFixture(t)
	f.login(t, "readonly", "mtls", pgtype.UUID{})
	f.grantCap(t, "db-writer", "db:login:writer") // NOT readonly

	// Mint-side gate.
	if _, err := f.sessSvc.CreatePostgresSession(f.ctx, f.user, f.asset, "readonly"); !errors.Is(err, session.ErrNoAccess) {
		t.Fatalf("CreatePostgresSession err = %v, want ErrNoAccess", err)
	}

	// Setup-side defense-in-depth: raw-mint a postgres bearer for readonly and redeem it.
	tok, err := f.minter.Mint(sessiontoken.Claims{
		SessionID: uuid.New(), UserID: f.user, AssetID: f.asset,
		Protocol: "postgres", Mode: "web", Login: "readonly",
	}, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := f.setupSvc.Setup(f.ctx, tok, "worker-1", "readonly", nil, nil); !errors.Is(err, dataplane.ErrNotAuthorized) {
		t.Fatalf("Setup err = %v, want ErrNotAuthorized", err)
	}
}
