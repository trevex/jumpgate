package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func caps(xs ...string) []byte { b, _ := json.Marshal(xs); return b }

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

// initSSHCA generates an SSH CA, seals its seed, stores it, and returns the CA's
// authorized_keys public line (for CertChecker.IsUserAuthority).
func initSSHCA(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) string {
	t.Helper()
	ctx := context.Background()
	seed, line, err := ca.GenerateSSHCA()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gen.New(pool).CreateCAKey(ctx, gen.CreateCAKeyParams{
		Kind: "ssh", Sealed: sealed, PublicMaterial: line,
	}); err != nil {
		t.Fatal(err)
	}
	return line
}

// clientKey generates an ephemeral ed25519 client key and returns its public key
// in authorized_keys form (the ClientSSHPubKey the broker signs).
func clientKey(t *testing.T) []byte {
	t.Helper()
	_, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cpub, err := ssh.NewPublicKey(cpriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(cpub)
}

// mkAsset creates a folder + asset of the given kind and returns the asset id.
func mkAsset(t *testing.T, q *gen.Queries, kind string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	f, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "f-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	a, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: f.ID, Name: "a-" + uuid.NewString()[:8], Labels: []byte("{}"), Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func mkUser(t *testing.T, q *gen.Queries) uuid.UUID {
	t.Helper()
	u, err := q.CreateUser(context.Background(), gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// bindRole creates a role with the given capabilities and a STANDING binding of
// it to the user on the asset.
func bindRole(t *testing.T, q *gen.Queries, user, asset uuid.UUID, name string, capsList ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name + "-" + uuid.NewString()[:8], ResourceType: "asset", Capabilities: caps(capsList...)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: r.ID, ScopeAssetID: pgUUID(asset), SubjectUserID: pgUUID(user),
	}); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// setSSHConfig upserts the ssh_asset_config for an asset.
func setSSHConfig(t *testing.T, q *gen.Queries, asset uuid.UUID, logins []string, authMethod string, storedSecret pgtype.UUID) {
	t.Helper()
	if _, err := q.UpsertSSHAssetConfig(context.Background(), gen.UpsertSSHAssetConfigParams{
		AssetID: asset, AllowedLogins: logins, AuthMethod: authMethod, StoredSecretID: storedSecret,
	}); err != nil {
		t.Fatal(err)
	}
}

// grantOpts / fabricateGrant mirror the authz test helper: write an
// access_requests row and an access_grants row directly so an active/expired
// grant matrix is exercisable.
type grantOpts struct {
	expiresIn time.Duration
	revoked   bool
}

func fabricateGrant(t *testing.T, pool *pgxpool.Pool, user, role, asset uuid.UUID, o grantOpts) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var reqID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_requests (requester_user_id, role_id, asset_id, requested_duration, required_approvals, granted_duration, status, resolved_at)
VALUES ($1, $2, $3, '1 hour', 1, '1 hour', 'granted', now())
RETURNING id`, user, role, asset).Scan(&reqID); err != nil {
		t.Fatalf("fabricate access_request: %v", err)
	}
	var grantID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_grants (request_id, role_id, scope_asset_id, subject_user_id, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, now() + $5::interval, CASE WHEN $6::bool THEN now() ELSE NULL END)
RETURNING id`, reqID, role, asset, user, o.expiresIn.String(), o.revoked).Scan(&grantID); err != nil {
		t.Fatalf("fabricate access_grant: %v", err)
	}
	return grantID
}

// parseCert parses an ssh-cert credential back into an *ssh.Certificate.
func parseCert(t *testing.T, cred Credential) *ssh.Certificate {
	t.Helper()
	if cred.Kind != "ssh-cert" {
		t.Fatalf("credential kind = %q, want ssh-cert", cred.Kind)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cred.SSHCertificate)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert): %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", pub)
	}
	return cert
}

// caAuthority parses the CA authorized_keys line into an ssh.PublicKey for
// CertChecker.IsUserAuthority.
func caAuthority(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse CA line: %v", err)
	}
	return pub
}

func newBroker(pool *pgxpool.Pool, sealer *secrets.Sealer) *Broker {
	return NewBroker(pool, sealer, authz.NewSQLAuthorizer(pool), audit.New(pool))
}

// TestIssuePrincipalsFromCaps: principals = allowed_logins ∩ entitled logins.
// Role grants ssh:login:root only; deploy is allowed on the asset but NOT
// entitled, so the cert's ValidPrincipals is exactly [root].
func TestIssuePrincipalsFromCaps(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	caLine := initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root", "deploy"}, "ca-cert", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-root", "ssh:login:root")

	b := newBroker(pool, sealer)
	validUntil := time.Now().Add(time.Hour)
	creds, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: validUntil, KeyID: "g1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	cert := parseCert(t, creds[0])

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("ValidPrincipals = %v, want [root] (deploy allowed but not entitled)", cert.ValidPrincipals)
	}
	if cert.KeyId != "g1" {
		t.Fatalf("KeyId = %q, want g1", cert.KeyId)
	}
	if delta := int64(cert.ValidBefore) - validUntil.Unix(); delta < -2 || delta > 2 { //nolint:gosec // Unix seconds fit int64
		t.Fatalf("ValidBefore = %d, want ≈ %d", cert.ValidBefore, validUntil.Unix())
	}

	// The cert verifies against the CA.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caAuthority(t, caLine).Marshal())
		},
	}
	if err := checker.CheckCert("root", cert); err != nil {
		t.Fatalf("CheckCert(root): %v", err)
	}
}

// TestIssueGlobPrincipals: a glob cap ssh:login:* entitles every allowed login.
func TestIssueGlobPrincipals(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root", "deploy"}, "ca-cert", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-all", "ssh:login:*")

	b := newBroker(pool, sealer)
	creds, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g2"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cert := parseCert(t, creds[0])
	got := map[string]bool{}
	for _, p := range cert.ValidPrincipals {
		got[p] = true
	}
	if !got["root"] || !got["deploy"] || len(cert.ValidPrincipals) != 2 {
		t.Fatalf("ValidPrincipals = %v, want {root, deploy}", cert.ValidPrincipals)
	}
}

// TestIssueNoEntitlement: a user with no ssh:login:* cap gets ErrNoLoginEntitlement,
// no cert, and NO audit event.
func TestIssueNoEntitlement(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root", "deploy"}, "ca-cert", pgtype.UUID{})
	// Bind an unrelated capability so the user has a role but no login entitlement.
	bindRole(t, q, alice, asset, "ssh-none", "db:read")

	b := newBroker(pool, sealer)
	creds, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g3"})
	if !errors.Is(err, ErrNoLoginEntitlement) {
		t.Fatalf("Issue err = %v, want ErrNoLoginEntitlement", err)
	}
	if creds != nil {
		t.Fatalf("creds = %v, want nil", creds)
	}
	assertNoCredentialAudit(t, pool)
}

// TestIssueViaActiveGrant: alice holds the ssh-root role via an ACTIVE grant →
// principal [root]. An expired grant → ErrNoLoginEntitlement.
func TestIssueViaActiveGrant(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root", "deploy"}, "ca-cert", pgtype.UUID{})
	// A role carrying ssh:login:root, but NOT standing-bound to anyone.
	sshRoot, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "ssh-root-grant", ResourceType: "asset", Capabilities: caps("ssh:login:root")})
	if err != nil {
		t.Fatal(err)
	}

	b := newBroker(pool, sealer)

	// Active grant → principal [root].
	alice := mkUser(t, q)
	fabricateGrant(t, pool, alice, sshRoot.ID, asset, grantOpts{expiresIn: time.Hour})
	creds, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g4"})
	if err != nil {
		t.Fatalf("Issue via active grant: %v", err)
	}
	cert := parseCert(t, creds[0])
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("ValidPrincipals = %v, want [root]", cert.ValidPrincipals)
	}

	// Expired grant → no entitlement.
	bob := mkUser(t, q)
	fabricateGrant(t, pool, bob, sshRoot.ID, asset, grantOpts{expiresIn: -time.Minute})
	if _, err := b.Issue(ctx, bob, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g5"}); !errors.Is(err, ErrNoLoginEntitlement) {
		t.Fatalf("Issue via expired grant err = %v, want ErrNoLoginEntitlement", err)
	}
}

// TestIssueStoredKey: auth_method stored-key → the sealed asset secret is opened
// and returned as a "secret" credential (no cert).
func TestIssueStoredKey(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	sealed, err := sealer.Seal([]byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := q.SetAssetSecret(ctx, gen.SetAssetSecretParams{AssetID: asset, Name: "ssh-key", Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	setSSHConfig(t, q, asset, []string{"root"}, "stored-key", pgUUID(sec.ID))

	b := newBroker(pool, sealer)
	creds, err := b.Issue(ctx, alice, asset, IssueRequest{ValidUntil: time.Now().Add(time.Hour), KeyID: "g6"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(creds) != 1 || creds[0].Kind != "secret" {
		t.Fatalf("creds = %+v, want single secret", creds)
	}
	if string(creds[0].Secret) != "s3cr3t" {
		t.Fatalf("Secret = %q, want s3cr3t", creds[0].Secret)
	}
	if creds[0].SSHCertificate != nil {
		t.Fatalf("stored-key must not return a cert")
	}
}

// TestIssueNoCA: the ca-cert path with no ca_keys row → ErrNoCA.
func TestIssueNoCA(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	// NOTE: no initSSHCA.

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root"}, "ca-cert", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-root", "ssh:login:root")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g7"}); !errors.Is(err, ErrNoCA) {
		t.Fatalf("Issue err = %v, want ErrNoCA", err)
	}
}

// TestIssueVaultDisabled: nil sealer → ErrVaultNotConfigured (fail closed).
func TestIssueVaultDisabled(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root"}, "ca-cert", pgtype.UUID{})

	b := NewBroker(pool, nil, authz.NewSQLAuthorizer(pool), audit.New(pool))
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g8"}); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatalf("Issue err = %v, want ErrVaultNotConfigured", err)
	}
}

// TestIssueUnsupportedKind: a postgres asset → ErrUnsupportedKind.
func TestIssueUnsupportedKind(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "postgres")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{ValidUntil: time.Now().Add(time.Hour), KeyID: "g9"}); !errors.Is(err, ErrUnsupportedKind) {
		t.Fatalf("Issue err = %v, want ErrUnsupportedKind", err)
	}
}

// TestIssueAudit: a successful ssh-ca issue writes a credential.issued audit
// entry and the chain verifies.
func TestIssueAudit(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset, []string{"root"}, "ca-cert", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-root", "ssh:login:root")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g10"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rows, err := q.ListAuditEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.EventType == EventCredentialIssued {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s audit entry found", EventCredentialIssued)
	}
	if err := audit.New(pool).Verify(ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// assertNoCredentialAudit asserts no credential.issued entry exists.
func assertNoCredentialAudit(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	rows, err := gen.New(pool).ListAuditEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.EventType == EventCredentialIssued {
			t.Fatalf("unexpected %s audit entry on a denied issuance", EventCredentialIssued)
		}
	}
}
