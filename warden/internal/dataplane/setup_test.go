package dataplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func capsJSON(xs ...string) []byte { b, _ := json.Marshal(xs); return b }

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	s, err := secrets.NewSealer(kek)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// initSSHCA generates + seals + stores an active SSH CA.
func initSSHCA(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) {
	t.Helper()
	seed, line, err := ca.GenerateSSHCA()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gen.New(pool).CreateCAKey(context.Background(), gen.CreateCAKeyParams{
		Kind: "ssh", Sealed: sealed, PublicMaterial: line,
	}); err != nil {
		t.Fatal(err)
	}
}

// fixture bundles a wired SetupService plus the seeded ids and a client keypair.
type fixture struct {
	pool *pgxpool.Pool
	q    *gen.Queries
	svc  *dataplane.SetupService
	ctx  context.Context

	user  uuid.UUID
	asset uuid.UUID
	role  uuid.UUID

	minter   *sessiontoken.Minter
	verifier *sessiontoken.Verifier

	clientPub []byte // Kc — authorized_keys form (cnf-bound)
	clientFp  string // ssh.FingerprintSHA256(Kc)

	workerPub []byte // Kw — authorized_keys form (certified for the target)
}

// newSSHKeypair returns a fresh ed25519 SSH keypair in authorized_keys form.
func newSSHKeypair(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(pub)
}

// setup seeds a full fixture: an ssh asset with target_address + allowed_logins
// {deploy}, a role carrying ssh:login:deploy standing-bound to the user, an
// active SSH CA, and a session-token Minter/Verifier over a fresh ed25519 key.
func setup(t *testing.T) *fixture {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	// User + asset.
	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	// ssh_asset_config: allowed_logins {deploy}, ca-cert. UpsertSSHAssetConfig
	// does not set target_address, so set it directly afterwards.
	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, AllowedLogins: []string{"deploy"}, AuthMethod: "ca-cert", StoredSecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ssh_asset_config SET target_address = $1 WHERE asset_id = $2`, "10.0.0.5:22", asset.ID); err != nil {
		t.Fatalf("set target_address: %v", err)
	}

	// Role carrying ssh:login:deploy, standing-bound to the user on the asset.
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "ssh-deploy", ResourceType: "asset", Capabilities: capsJSON("ssh:login:deploy")})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pg(asset.ID), SubjectUserID: pg(user.ID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	// Session-token signing key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	minter := sessiontoken.NewMinter(priv)
	verifier := sessiontoken.NewVerifier(pub)

	// Client ephemeral SSH keypair.
	_, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cpub, err := ssh.NewPublicKey(cpriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientPub := ssh.MarshalAuthorizedKey(cpub)
	clientFp := ssh.FingerprintSHA256(cpub)

	// Worker per-session SSH keypair (Kw) — distinct from the client key; this is
	// the key warden certifies for the target hop.
	workerPub := newSSHKeypair(t)

	broker := vault.NewBroker(pool, sealer, authz.NewSQLAuthorizer(pool), audit.New(pool))
	svc := dataplane.NewSetupService(pool, verifier, authz.NewSQLAuthorizer(pool), broker, audit.New(pool), time.Hour)

	return &fixture{
		pool: pool, q: q, svc: svc, ctx: ctx,
		user: user.ID, asset: asset.ID, role: role.ID,
		minter: minter, verifier: verifier, clientPub: clientPub, clientFp: clientFp,
		workerPub: workerPub,
	}
}

// mintToken mints a session token binding the given client fingerprint.
func (f *fixture) mintToken(t *testing.T, fp string) string {
	t.Helper()
	tok, err := f.minter.Mint(sessiontoken.Claims{
		SessionID:            uuid.New(),
		UserID:               f.user,
		AssetID:              f.asset,
		Protocol:             "ssh",
		ClientKeyFingerprint: fp,
	}, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return tok
}

func (f *fixture) liveSessionCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM live_sessions`).Scan(&n); err != nil {
		t.Fatalf("count live_sessions: %v", err)
	}
	return n
}

func (f *fixture) drainAudit(t *testing.T) {
	t.Helper()
	for {
		n, err := audit.New(f.pool).DrainOnce(f.ctx, 256)
		if err != nil {
			t.Fatalf("DrainOnce: %v", err)
		}
		if n < 256 {
			return
		}
	}
}

func TestSetupSessionHappyPath(t *testing.T) {
	f := setup(t)
	tok := f.mintToken(t, f.clientFp)

	res, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res.TargetAddress != "10.0.0.5:22" {
		t.Fatalf("TargetAddress = %q, want 10.0.0.5:22", res.TargetAddress)
	}
	if len(res.SSHCertificate) == 0 {
		t.Fatal("expected a non-empty ssh certificate")
	}
	if res.SessionID == "" {
		t.Fatal("expected a non-empty session id")
	}

	// A live_sessions row exists with principals == [deploy].
	rows, err := f.q.ListLiveSessionsByUserAsset(f.ctx, gen.ListLiveSessionsByUserAssetParams{UserID: f.user, AssetID: f.asset})
	if err != nil {
		t.Fatalf("ListLiveSessionsByUserAsset: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("live_sessions rows = %d, want 1", len(rows))
	}
	if len(rows[0].Principals) != 1 || rows[0].Principals[0] != "deploy" {
		t.Fatalf("Principals = %v, want [deploy]", rows[0].Principals)
	}
	if rows[0].GrantID.Valid {
		t.Fatalf("GrantID = %v, want NULL", rows[0].GrantID)
	}

	// The cert carries ValidPrincipals == [deploy].
	pub, _, _, _, err := ssh.ParseAuthorizedKey(res.SSHCertificate)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert): %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", pub)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Fatalf("cert ValidPrincipals = %v, want [deploy]", cert.ValidPrincipals)
	}

	// The cert is over Kw (the worker key), NOT Kc (the client key). This is the
	// core M4c invariant: the client proves Kc via cnf, but the target hop is
	// certified against the worker's own per-session key.
	kwPub, _, _, _, err := ssh.ParseAuthorizedKey(f.workerPub)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(Kw): %v", err)
	}
	kcPub, _, _, _, err := ssh.ParseAuthorizedKey(f.clientPub)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(Kc): %v", err)
	}
	if !bytes.Equal(cert.Key.Marshal(), kwPub.Marshal()) {
		t.Fatal("cert.Key does not marshal to Kw (the worker key)")
	}
	if bytes.Equal(cert.Key.Marshal(), kcPub.Marshal()) {
		t.Fatal("cert.Key marshals to Kc (the client key) — must be over Kw, not Kc")
	}

	// SessionID equals the token's session id.
	claims, err := f.verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if res.SessionID != claims.SessionID.String() {
		t.Fatalf("SessionID = %q, want %q", res.SessionID, claims.SessionID.String())
	}

	// The session.started event is present after a drain and the chain verifies.
	f.drainAudit(t)
	entries, err := f.q.ListAuditEntries(f.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.EventType == dataplane.EventSessionStarted {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s audit entry found", dataplane.EventSessionStarted)
	}
	if err := audit.New(f.pool).Verify(f.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestSetupComputesRecordingRequirement asserts recording is mandatory by default
// (a date-partitioned object key is handed to the worker), and that holding the
// ssh:record:exempt capability on the asset waives it.
func TestSetupComputesRecordingRequirement(t *testing.T) {
	f := setup(t)

	// Default scenario: no exemption → recording required, with a well-formed key.
	tok := f.mintToken(t, f.clientFp)
	claims, err := f.verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	sessionID := claims.SessionID.String()

	res, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !res.RecordingRequired {
		t.Fatal("RecordingRequired = false, want true (recording is mandatory by default)")
	}
	if !strings.HasPrefix(res.RecordingObjectKey, "recordings/ssh/") {
		t.Fatalf("RecordingObjectKey = %q, want prefix recordings/ssh/", res.RecordingObjectKey)
	}
	if !strings.HasSuffix(res.RecordingObjectKey, "/"+sessionID+".cast") {
		t.Fatalf("RecordingObjectKey = %q, want suffix /%s.cast", res.RecordingObjectKey, sessionID)
	}

	// Exempt scenario: bind a role carrying ssh:record:exempt to the same user on
	// the same asset, then drive a fresh Setup (new token/session).
	exemptRole, err := f.q.CreateRole(f.ctx, gen.CreateRoleParams{
		Name: "ssh-record-exempt", ResourceType: "asset", Capabilities: capsJSON("ssh:record:exempt"),
	})
	if err != nil {
		t.Fatalf("CreateRole(exempt): %v", err)
	}
	if _, err := f.q.CreateRoleBinding(f.ctx, gen.CreateRoleBindingParams{
		RoleID: exemptRole.ID, ScopeAssetID: pg(f.asset), SubjectUserID: pg(f.user),
	}); err != nil {
		t.Fatalf("CreateRoleBinding(exempt): %v", err)
	}

	tok2 := f.mintToken(t, f.clientFp)
	res2, err := f.svc.Setup(f.ctx, tok2, "worker-1", f.clientPub, f.workerPub)
	if err != nil {
		t.Fatalf("Setup(exempt): %v", err)
	}
	if res2.RecordingRequired {
		t.Fatal("RecordingRequired = true, want false (user holds ssh:record:exempt)")
	}
}

func TestSetupSessionCnfMismatch(t *testing.T) {
	f := setup(t)
	// Mint a token bound to a DIFFERENT client key.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := ssh.NewPublicKey(otherPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	tok := f.mintToken(t, ssh.FingerprintSHA256(otherPub))

	// Present OUR client key, which does not match the token's cnf. Kw is arbitrary.
	if _, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub); !errors.Is(err, dataplane.ErrKeyMismatch) {
		t.Fatalf("Setup err = %v, want ErrKeyMismatch", err)
	}
	if n := f.liveSessionCount(t); n != 0 {
		t.Fatalf("live_sessions rows = %d, want 0", n)
	}
}

func TestSetupSessionRevokedBeforeConnect(t *testing.T) {
	f := setup(t)
	tok := f.mintToken(t, f.clientFp)

	// Revoke the entitlement AFTER minting: delete the role binding.
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM role_bindings WHERE role_id = $1 AND subject_user_id = $2`, f.role, f.user); err != nil {
		t.Fatalf("delete role binding: %v", err)
	}

	if _, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub); !errors.Is(err, dataplane.ErrNotAuthorized) {
		t.Fatalf("Setup err = %v, want ErrNotAuthorized", err)
	}
	if n := f.liveSessionCount(t); n != 0 {
		t.Fatalf("live_sessions rows = %d, want 0", n)
	}
}

func TestSetupSessionReplay(t *testing.T) {
	f := setup(t)
	tok := f.mintToken(t, f.clientFp)

	if _, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub); err != nil {
		t.Fatalf("first Setup: %v", err)
	}
	// Replaying the same token+key → PK conflict → ErrReplay.
	if _, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub); !errors.Is(err, dataplane.ErrReplay) {
		t.Fatalf("second Setup err = %v, want ErrReplay", err)
	}
	if n := f.liveSessionCount(t); n != 1 {
		t.Fatalf("live_sessions rows = %d, want exactly 1", n)
	}
}

// TestSetupCertifiesWorkerKeyNotClient asserts the returned cert is over Kw (the
// worker's per-session key) and NOT Kc (the cnf-bound client key). The cnf check
// binds Kc; the certified key is Kw — the two must never be conflated.
func TestSetupCertifiesWorkerKeyNotClient(t *testing.T) {
	f := setup(t)
	tok := f.mintToken(t, f.clientFp)

	res, err := f.svc.Setup(f.ctx, tok, "worker-1", f.clientPub, f.workerPub)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(res.SSHCertificate)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert): %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", pub)
	}

	kwPub, _, _, _, err := ssh.ParseAuthorizedKey(f.workerPub)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(Kw): %v", err)
	}
	kcPub, _, _, _, err := ssh.ParseAuthorizedKey(f.clientPub)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(Kc): %v", err)
	}
	if bytes.Equal(cert.Key.Marshal(), kcPub.Marshal()) {
		t.Fatal("cert.Key == Kc — the cert must NOT be over the client key")
	}
	if !bytes.Equal(cert.Key.Marshal(), kwPub.Marshal()) {
		t.Fatal("cert.Key != Kw — the cert must be over the worker key")
	}
}
