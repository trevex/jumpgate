package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
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
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// insertRoleCaps populates a role's capabilities in the role_capabilities table
// (the jsonb roles.capabilities column was dropped in favour of the normalized
// (scope, action, qualifier) rows), mirroring the production role-creation path.
func insertRoleCaps(ctx context.Context, t *testing.T, q *sqlc.Queries, roleID uuid.UUID, patterns ...string) {
	t.Helper()
	for _, pat := range patterns {
		sc, ac, qu := authz.NormalizeCap(pat)
		if err := q.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{
			RoleID: roleID, Scope: sc, Action: ac, Qualifier: qu,
		}); err != nil {
			t.Fatalf("insert role capability %q: %v", pat, err)
		}
	}
}

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
	if _, err := sqlc.New(pool).CreateCAKey(ctx, sqlc.CreateCAKeyParams{
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
func mkAsset(t *testing.T, q *sqlc.Queries, kind string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	f, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "f-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: f.ID, Name: "a-" + uuid.NewString()[:8], Labels: []byte("{}"), Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func mkUser(t *testing.T, q *sqlc.Queries) uuid.UUID {
	t.Helper()
	u, err := q.CreateUser(context.Background(), sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// bindRole creates a role with the given capabilities and a STANDING binding of
// it to the user on the asset.
func bindRole(t *testing.T, q *sqlc.Queries, user, asset uuid.UUID, name string, capsList ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	r, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: name + "-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	insertRoleCaps(ctx, t, q, r.ID, capsList...)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: r.ID, ScopeAssetID: pgUUID(asset), SubjectUserID: pgUUID(user),
	}); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// setSSHConfig upserts the ssh_asset_config (host/target) for an asset.
func setSSHConfig(t *testing.T, q *sqlc.Queries, asset uuid.UUID) {
	t.Helper()
	if _, err := q.UpsertSSHAssetConfig(context.Background(), sqlc.UpsertSSHAssetConfigParams{
		AssetID: asset, HostPublicKey: "", TargetAddress: "target:22",
	}); err != nil {
		t.Fatal(err)
	}
}

// setLogin upserts one ssh_asset_login row (kind ca has no secret).
func setLogin(t *testing.T, q *sqlc.Queries, asset uuid.UUID, login, kind string, secret pgtype.UUID) {
	t.Helper()
	if _, err := q.UpsertSSHAssetLogin(context.Background(), sqlc.UpsertSSHAssetLoginParams{
		AssetID: asset, Login: login, Kind: kind, SecretID: secret,
	}); err != nil {
		t.Fatalf("upsert ssh asset login %q/%q: %v", login, kind, err)
	}
}

// wantAssetPrincipals derives the host-scoped principals warden must mint for
// (login, asset): [login@<folder-path>.<asset-name>, login@<asset-id>]. Reading
// the path back via the same FolderPath query the broker uses keeps the fixture
// in step with randomized folder/asset names.
func wantAssetPrincipals(t *testing.T, q *sqlc.Queries, assetID uuid.UUID, login string) []string {
	t.Helper()
	ctx := context.Background()
	a, err := q.GetAsset(ctx, assetID)
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	fp, err := q.FolderPath(ctx, a.FolderID)
	if err != nil {
		t.Fatalf("folder path: %v", err)
	}
	path := a.Name
	if fp != "" {
		path += "." + fp
	}
	return []string{login + "@" + path, login + "@" + a.ID.String()}
}

// sealSecret seals the value under the sealer and stores it as an asset secret,
// returning the secret id.
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
	return NewBroker(pool, sealer, authz.New(pool), audit.New(pool))
}

// TestIssueCaHostScopedPrincipals: a ca login yields a cert whose
// ValidPrincipals are host-scoped [login@<asset-path>, login@<asset-id>], even
// though the user is entitled to others. deploy is allowed but not requested;
// only root is signed, in host-scoped form.
func TestIssueCaHostScopedPrincipals(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)
	caLine := initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})
	setLogin(t, q, asset, "deploy", "ca", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-all", "ssh:login:*")

	b := newBroker(pool, sealer)
	validUntil := time.Now().Add(time.Hour)
	cred, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: validUntil, KeyID: "g1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cert := parseCert(t, cred)

	want := wantAssetPrincipals(t, q, asset, "root")
	if !slices.Equal(cert.ValidPrincipals, want) {
		t.Fatalf("ValidPrincipals = %v, want %v (host-scoped)", cert.ValidPrincipals, want)
	}
	// The id-form principal is fully deterministic — assert it independently.
	if cert.ValidPrincipals[1] != "root@"+asset.String() {
		t.Fatalf("id principal = %q, want root@%s", cert.ValidPrincipals[1], asset)
	}
	if cert.KeyId != "g1" {
		t.Fatalf("KeyId = %q, want g1", cert.KeyId)
	}
	if delta := int64(cert.ValidBefore) - validUntil.Unix(); delta < -2 || delta > 2 { //nolint:gosec // Unix seconds fit int64
		t.Fatalf("ValidBefore = %d, want ≈ %d", cert.ValidBefore, validUntil.Unix())
	}

	// The cert verifies against the CA using a host-scoped principal.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caAuthority(t, caLine).Marshal())
		},
	}
	// CheckCert validates the presented user is in ValidPrincipals; use the
	// path-form principal (want[0]) since it matches the human-readable asset path.
	if err := checker.CheckCert(want[0], cert); err != nil {
		t.Fatalf("CheckCert(%s): %v", want[0], err)
	}
}

// TestIssuePassword: a password login returns the sealed secret bytes.
func TestIssuePassword(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	secID := sealSecret(t, q, sealer, asset, "demo", []byte("hunter2"))
	setLogin(t, q, asset, "demo", "password", pgUUID(secID))
	bindRole(t, q, alice, asset, "ssh-demo", "ssh:login:demo")

	b := newBroker(pool, sealer)
	cred, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "demo", ValidUntil: time.Now().Add(time.Hour), KeyID: "g2"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.Kind != "ssh-password" {
		t.Fatalf("Kind = %q, want ssh-password", cred.Kind)
	}
	if string(cred.Secret) != "hunter2" {
		t.Fatalf("Secret = %q, want hunter2", cred.Secret)
	}
	if cred.SSHCertificate != nil {
		t.Fatalf("password must not return a cert")
	}
}

// TestIssueKey: a key login returns the sealed private-key bytes.
func TestIssueKey(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	secID := sealSecret(t, q, sealer, asset, "demo", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"))
	setLogin(t, q, asset, "demo", "key", pgUUID(secID))
	bindRole(t, q, alice, asset, "ssh-demo", "ssh:login:demo")

	b := newBroker(pool, sealer)
	cred, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "demo", ValidUntil: time.Now().Add(time.Hour), KeyID: "g3"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.Kind != "ssh-key" {
		t.Fatalf("Kind = %q, want ssh-key", cred.Kind)
	}
	if string(cred.Secret) != "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n" {
		t.Fatalf("Secret = %q, unexpected", cred.Secret)
	}
	if cred.SSHCertificate != nil {
		t.Fatalf("key must not return a cert")
	}
}

// TestIssueNoEntitlement: a user with no ssh:login:<L> cap gets
// ErrNoLoginEntitlement, no secret released, and NO audit event — even for the
// password kind (the stored-secret gap is closed).
func TestIssueNoEntitlement(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	secID := sealSecret(t, q, sealer, asset, "demo", []byte("hunter2"))
	setLogin(t, q, asset, "demo", "password", pgUUID(secID))
	// Bind an unrelated capability so the user has a role but no login entitlement.
	bindRole(t, q, alice, asset, "ssh-none", "db:read")

	b := newBroker(pool, sealer)
	cred, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "demo", ValidUntil: time.Now().Add(time.Hour), KeyID: "g4"})
	if !errors.Is(err, ErrNoLoginEntitlement) {
		t.Fatalf("Issue err = %v, want ErrNoLoginEntitlement", err)
	}
	if cred.Secret != nil || cred.SSHCertificate != nil {
		t.Fatalf("cred = %+v, want empty (nothing released)", cred)
	}
	assertNoCredentialAudit(t, pool)
}

// TestIssueAbsentLogin: a login not configured on the asset → sentinel, no audit.
func TestIssueAbsentLogin(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-all", "ssh:login:*")

	b := newBroker(pool, sealer)
	_, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "ghost", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g5"})
	if !errors.Is(err, ErrNoLoginEntitlement) {
		t.Fatalf("Issue err = %v, want ErrNoLoginEntitlement", err)
	}
	assertNoCredentialAudit(t, pool)
}

// TestIssueSecretIsAssetScoped: asset B's login cannot open asset A's secret.
// The composite FK forbids binding a foreign secret at write time; here we bypass
// the FK by inserting the login row directly with a foreign secret_id and assert
// the asset-scoped GetAssetSecret refuses to open it (defense in depth).
func TestIssueSecretIsAssetScoped(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	assetA := mkAsset(t, q, "ssh")
	assetB := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, assetB)
	// The secret belongs to asset A.
	foreignSec := sealSecret(t, q, sealer, assetA, "demo", []byte("A-secret"))
	// The composite FK ssh_login_secret_same_asset structurally forbids binding
	// asset A's secret to asset B's login. Drop it just for this row so we can
	// exercise the broker's independent asset-scoped GetAssetSecret guard (defense
	// in depth behind the FK).
	if _, err := pool.Exec(ctx, `ALTER TABLE ssh_asset_login DROP CONSTRAINT ssh_login_secret_same_asset`); err != nil {
		t.Fatalf("drop composite FK: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO ssh_asset_login (asset_id, login, kind, secret_id) VALUES ($1, 'demo', 'password', $2)`,
		assetB, foreignSec); err != nil {
		t.Fatalf("insert foreign login: %v", err)
	}
	bindRole(t, q, alice, assetB, "ssh-demo", "ssh:login:demo")

	b := newBroker(pool, sealer)
	_, err := b.Issue(ctx, alice, assetB, IssueRequest{Login: "demo", ValidUntil: time.Now().Add(time.Hour), KeyID: "g6"})
	if !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Issue err = %v, want ErrNoConfig (asset-scoped secret refused)", err)
	}
	assertNoCredentialAudit(t, pool)
}

// TestIssueViaActiveGrant: alice holds the ssh-root role via an ACTIVE grant →
// principal [root]. An expired grant → ErrNoLoginEntitlement.
func TestIssueViaActiveGrant(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})
	// A role carrying ssh:login:root, but NOT standing-bound to anyone.
	sshRoot, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "ssh-root-grant"})
	if err != nil {
		t.Fatal(err)
	}
	insertRoleCaps(ctx, t, q, sshRoot.ID, "ssh:login:root")

	b := newBroker(pool, sealer)

	// Active grant → principal [root].
	alice := mkUser(t, q)
	fabricateGrant(t, pool, alice, sshRoot.ID, asset, grantOpts{expiresIn: time.Hour})
	cred, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g7"})
	if err != nil {
		t.Fatalf("Issue via active grant: %v", err)
	}
	cert := parseCert(t, cred)
	want := wantAssetPrincipals(t, q, asset, "root")
	if !slices.Equal(cert.ValidPrincipals, want) {
		t.Fatalf("ValidPrincipals = %v, want %v (host-scoped)", cert.ValidPrincipals, want)
	}
	if cert.ValidPrincipals[1] != "root@"+asset.String() {
		t.Fatalf("id principal = %q, want root@%s", cert.ValidPrincipals[1], asset)
	}

	// Expired grant → no entitlement.
	bob := mkUser(t, q)
	fabricateGrant(t, pool, bob, sshRoot.ID, asset, grantOpts{expiresIn: -time.Minute})
	if _, err := b.Issue(ctx, bob, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g8"}); !errors.Is(err, ErrNoLoginEntitlement) {
		t.Fatalf("Issue via expired grant err = %v, want ErrNoLoginEntitlement", err)
	}
}

// TestIssueNoCA: the ca path with no ca_keys row → ErrNoCA.
func TestIssueNoCA(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)
	// NOTE: no initSSHCA.

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-root", "ssh:login:root")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g9"}); !errors.Is(err, ErrNoCA) {
		t.Fatalf("Issue err = %v, want ErrNoCA", err)
	}
}

// TestIssueVaultDisabled: nil sealer → ErrVaultNotConfigured (fail closed).
func TestIssueVaultDisabled(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})

	b := NewBroker(pool, nil, authz.New(pool), audit.New(pool))
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g10"}); !errors.Is(err, ErrVaultNotConfigured) {
		t.Fatalf("Issue err = %v, want ErrVaultNotConfigured", err)
	}
}

// TestIssueUnsupportedKind: a postgres asset → ErrUnsupportedKind.
func TestIssueUnsupportedKind(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "postgres")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ValidUntil: time.Now().Add(time.Hour), KeyID: "g11"}); !errors.Is(err, ErrUnsupportedKind) {
		t.Fatalf("Issue err = %v, want ErrUnsupportedKind", err)
	}
}

// TestIssueAudit: a successful ssh-ca issue writes a credential.issued audit
// entry and the chain verifies.
func TestIssueAudit(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	sealer := newSealer(t)
	initSSHCA(t, pool, sealer)

	alice := mkUser(t, q)
	asset := mkAsset(t, q, "ssh")
	setSSHConfig(t, q, asset)
	setLogin(t, q, asset, "root", "ca", pgtype.UUID{})
	bindRole(t, q, alice, asset, "ssh-root", "ssh:login:root")

	b := newBroker(pool, sealer)
	if _, err := b.Issue(ctx, alice, asset, IssueRequest{Login: "root", ClientSSHPubKey: clientKey(t), ValidUntil: time.Now().Add(time.Hour), KeyID: "g12"}); err != nil {
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
	rows, err := sqlc.New(pool).ListAuditEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.EventType == EventCredentialIssued {
			t.Fatalf("unexpected %s audit entry on a denied issuance", EventCredentialIssued)
		}
	}
}
