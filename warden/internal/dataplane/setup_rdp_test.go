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
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// rdpFixture is a wired rdp mint→redeem harness: an rdp asset, a shared
// minter/verifier ed25519 key across the SetupService and the session.Service,
// and a sealer for the password-only login. RDP has no CA/mtls arm — only
// stored-secret password logins — so no CA setup is needed here.
type rdpFixture struct {
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

// newRDPFixture seeds an rdp asset + user and wires the SetupService and
// session.Service over ONE ed25519 keypair (mint and verify must share it).
func newRDPFixture(t *testing.T) *rdpFixture {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "rdp-host", Labels: []byte("{}"), Kind: "rdp"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertRDPAssetConfig(ctx, sqlc.UpsertRDPAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "rdp-host:3389",
	}); err != nil {
		t.Fatalf("UpsertRDPAssetConfig: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minter := sessiontoken.NewMinter(priv)
	verifier := sessiontoken.NewVerifier(pub)

	broker := vault.NewBroker(pool, sealer, authz.New(pool), audit.New(pool))
	identity := targetidentity.NewService(pool, audit.New(pool))
	setupSvc := dataplane.NewSetupService(pool, verifier, authz.New(pool), broker, identity, audit.New(pool), time.Hour)
	sessSvc := session.NewService(q, authz.New(pool), minter, "gw:443", "", false, time.Hour, dataplane.NewRegistry(), nil)

	return &rdpFixture{
		pool: pool, q: q, sealer: sealer, ctx: ctx,
		user: user.ID, asset: asset.ID,
		setupSvc: setupSvc, sessSvc: sessSvc, minter: minter,
	}
}

// login upserts an rdp asset login of the given login/kind (optional secret).
func (f *rdpFixture) login(t *testing.T, login, kind string, secret pgtype.UUID) {
	t.Helper()
	if _, err := f.q.UpsertRDPAssetLogin(f.ctx, sqlc.UpsertRDPAssetLoginParams{
		AssetID: f.asset, Login: login, Kind: kind, SecretID: secret,
	}); err != nil {
		t.Fatalf("UpsertRDPAssetLogin %q/%q: %v", login, kind, err)
	}
}

// grantCap creates a role carrying cap and standing-binds it to the user on the asset.
func (f *rdpFixture) grantCap(t *testing.T, name, capPat string) {
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

// liveSessionProtocol reads the protocol column of the given live session.
func (f *rdpFixture) liveSessionProtocol(t *testing.T, sessionID string) string {
	t.Helper()
	var proto string
	if err := f.pool.QueryRow(f.ctx, `SELECT protocol FROM live_sessions WHERE id=$1`, sessionID).Scan(&proto); err != nil {
		t.Fatalf("query live_sessions protocol: %v", err)
	}
	return proto
}

// approveTLSLeaf seeds an active tls_leaf trust anchor for the asset at its current
// endpoint revision and returns its id + fingerprint (exact-match at issue time).
func (f *rdpFixture) approveTLSLeaf(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	asset, err := f.q.GetAsset(f.ctx, f.asset)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	fp := "SHA256:" + uuid.NewString()
	row, err := f.q.ApproveTrustAnchor(f.ctx, sqlc.ApproveTrustAnchorParams{
		AssetID:               f.asset,
		EndpointRevision:      asset.EndpointRevision,
		Kind:                  "tls_leaf",
		Algorithm:             "rsa",
		Sha256Fingerprint:     fp,
		PublicMaterial:        "-----BEGIN CERTIFICATE-----\nMIIBLEAF\n-----END CERTIFICATE-----",
		RequiredSshPrincipals: []string{},
		RequiredDnsNames:      []string{},
		RequiredIpAddresses:   []string{},
		Source:                "manual",
		ApprovedBy:            pgtype.UUID{Bytes: f.user, Valid: true},
		ApprovedAt:            pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
	})
	if err != nil {
		t.Fatalf("ApproveTrustAnchor: %v", err)
	}
	return row.ID, fp
}

// TestSetupRDPPassword drives the happy path for a password login: mint an rdp
// bearer ticket, redeem it, and assert the credential surfaces through the
// generic Password arm (rdp has no dedicated proto oneof), and that the session
// is marked recording-required with a .rdpg (rdp-graphics-v1) object key.
func TestSetupRDPPassword(t *testing.T) {
	f := newRDPFixture(t)
	secID := sealSecret(t, f.q, f.sealer, f.asset, "admin", []byte("s3cr3t"))
	f.login(t, "admin", "password", pgtype.UUID{Bytes: secID, Valid: true})
	f.grantCap(t, "rdp-admin", "rdp:login:admin")

	anchorID, fp := f.approveTLSLeaf(t)
	created, err := f.sessSvc.CreateRDPSession(f.ctx, f.user, f.asset, "admin", false)
	if err != nil {
		t.Fatalf("CreateRDPSession: %v", err)
	}

	prep, err := f.setupSvc.Prepare(f.ctx, created.Token, "worker-1", "admin", nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.TargetAddress != "rdp-host:3389" {
		t.Fatalf("TargetAddress = %q, want rdp-host:3389", prep.TargetAddress)
	}
	if !prep.RecordingRequired {
		t.Error("rdp prepare: RecordingRequired = false, want true (rdp-graphics-v1 is always recorded)")
	}
	if !strings.HasSuffix(prep.RecordingObjectKey, ".rdpg") {
		t.Errorf("rdp prepare: RecordingObjectKey = %q, want a .rdpg key", prep.RecordingObjectKey)
	}
	if got := f.liveSessionProtocol(t, prep.SessionID); got != "rdp" {
		t.Fatalf("live_sessions.protocol = %q, want rdp", got)
	}

	res, err := f.setupSvc.IssueCredential(f.ctx, prep.SessionID, "worker-1", prep.EndpointRevision, anchorID.String(), fp, nil)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}
	if res.CredentialKind != "rdp-password" {
		t.Fatalf("CredentialKind = %q, want rdp-password", res.CredentialKind)
	}
	// The rdp password must surface through the generic Password field, the same
	// arm ssh-password/pg-password use — no dedicated proto oneof for rdp.
	if res.Password != "s3cr3t" {
		t.Fatalf("Password = %q, want s3cr3t", res.Password)
	}
	if res.Login != "admin" {
		t.Fatalf("Login = %q, want admin", res.Login)
	}
}

// TestSetupRDPUnentitled asserts the rdp:login gate on both sides: the user
// holds rdp:login:guest, not the requested admin, so the mint is refused
// (ErrNoAccess) and a raw-minted admin ticket is refused at Setup (ErrNotAuthorized).
func TestSetupRDPUnentitled(t *testing.T) {
	f := newRDPFixture(t)
	secID := sealSecret(t, f.q, f.sealer, f.asset, "admin", []byte("s3cr3t"))
	f.login(t, "admin", "password", pgtype.UUID{Bytes: secID, Valid: true})
	f.grantCap(t, "rdp-guest", "rdp:login:guest") // NOT admin

	// Mint-side gate.
	if _, err := f.sessSvc.CreateRDPSession(f.ctx, f.user, f.asset, "admin", false); !errors.Is(err, session.ErrNoAccess) {
		t.Fatalf("CreateRDPSession err = %v, want ErrNoAccess", err)
	}

	// Setup-side defense-in-depth: raw-mint an rdp bearer for admin and redeem it.
	tok, err := f.minter.Mint(sessiontoken.Claims{
		SessionID: uuid.New(), UserID: f.user, AssetID: f.asset,
		Protocol: "rdp", Mode: "web", Login: "admin",
	}, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := f.setupSvc.Prepare(f.ctx, tok, "worker-1", "admin", nil); !errors.Is(err, dataplane.ErrNotAuthorized) {
		t.Fatalf("Prepare err = %v, want ErrNotAuthorized", err)
	}
}
