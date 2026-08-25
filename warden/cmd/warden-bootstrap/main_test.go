package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	gossh "golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// masterKeyB64 is a fixed, valid base64 32-byte VAULT_MASTER_KEY for the test.
const masterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

const (
	testAdminEmail = "admin@bootstrap.test"
	testAdminPass  = "bootstrap-admin-1234"
)

func TestBootstrapProvisions(t *testing.T) {
	// A valid 32-byte base64 key (sanity: the fixed constant decodes to 32 bytes).
	if k, err := base64.StdEncoding.DecodeString(masterKeyB64); err != nil || len(k) != 32 {
		t.Fatalf("masterKeyB64 must decode to 32 bytes: len=%d err=%v", len(k), err)
	}

	dsn := testsupport.StartPostgres(t)
	out := t.TempDir()

	cfg := config{
		dsn:           dsn,
		masterKeyB64:  masterKeyB64,
		outDir:        out,
		adminEmail:    testAdminEmail,
		adminPassword: testAdminPass,
	}

	ctx := context.Background()
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("run: %v", err)
	}

	pool, err := postgres.NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	q := sqlc.New(pool)

	// SSH CA row exists and the emitted public line parses as an SSH public key.
	sshRow, err := q.GetActiveCA(ctx, "ssh")
	if err != nil {
		t.Fatalf("GetActiveCA(ssh): %v", err)
	}
	sshPubBytes, err := os.ReadFile(filepath.Join(out, "ssh-ca.pub")) //nolint:gosec // test-controlled temp dir
	if err != nil {
		t.Fatalf("read ssh-ca.pub: %v", err)
	}
	if _, _, _, _, err := gossh.ParseAuthorizedKey(sshPubBytes); err != nil {
		t.Fatalf("parse ssh-ca.pub: %v", err)
	}

	// Mesh CA files exist and PEM-parse as a certificate and a private key.
	crtBytes, err := os.ReadFile(filepath.Join(out, "mesh-ca.crt")) //nolint:gosec // test-controlled temp dir
	if err != nil {
		t.Fatalf("read mesh-ca.crt: %v", err)
	}
	crtBlock, _ := pem.Decode(crtBytes)
	if crtBlock == nil {
		t.Fatalf("mesh-ca.crt has no PEM block")
	}
	if _, err := x509.ParseCertificate(crtBlock.Bytes); err != nil {
		t.Fatalf("parse mesh-ca.crt: %v", err)
	}
	keyBytes, err := os.ReadFile(filepath.Join(out, "mesh-ca.key")) //nolint:gosec // test-controlled temp dir
	if err != nil {
		t.Fatalf("read mesh-ca.key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		t.Fatalf("mesh-ca.key has no PEM block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("parse mesh-ca.key: %v", err)
	}

	// mesh-ca.key must be private (0600).
	if info, err := os.Stat(filepath.Join(out, "mesh-ca.key")); err != nil {
		t.Fatalf("stat mesh-ca.key: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mesh-ca.key perm = %o, want 600", perm)
	}

	// A session signing key exists (GetActiveSessionSigningKey returns no ErrNoRows).
	if _, err := q.GetActiveSessionSigningKey(ctx); err != nil {
		t.Fatalf("GetActiveSessionSigningKey: %v", err)
	}

	// The admin user exists.
	admin, err := q.GetUserByEmail(ctx, testAdminEmail)
	if err != nil {
		t.Fatalf("GetUserByEmail(admin): %v", err)
	}

	// A global `admin` role exists carrying the `**` (match-everything) capability.
	adminRole, err := q.GetRoleByNameGlobal(ctx, "admin")
	if err != nil {
		t.Fatalf("GetRoleByNameGlobal(admin): %v", err)
	}
	// Capabilities now live in role_capabilities as normalized (scope, action,
	// qualifier) rows (the jsonb roles.capabilities column was dropped).
	rows, err := pool.Query(ctx,
		`SELECT scope, action, qualifier FROM role_capabilities WHERE role_id = $1`, adminRole.ID)
	if err != nil {
		t.Fatalf("query admin role capabilities: %v", err)
	}
	var roleCaps []string
	for rows.Next() {
		var sc, ac, qu string
		if err := rows.Scan(&sc, &ac, &qu); err != nil {
			rows.Close()
			t.Fatalf("scan admin role capability: %v", err)
		}
		roleCaps = append(roleCaps, authz.ReconstructCap(sc, ac, qu))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("admin role capabilities rows: %v", err)
	}
	if len(roleCaps) != 1 || roleCaps[0] != "**" {
		t.Fatalf("admin role capabilities = %v, want [**]", roleCaps)
	}
	if adminRole.FolderID.Valid {
		t.Fatalf("admin role folder_id = %v, want NULL (global)", adminRole.FolderID)
	}

	// A scopeless (global) standing binding of the admin role to the admin user exists.
	var nBindings int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM role_bindings
		   WHERE role_id = $1 AND subject_user_id = $2
		     AND scope_folder_id IS NULL AND scope_asset_id IS NULL
		     AND subject_group_id IS NULL`,
		adminRole.ID, admin.ID).Scan(&nBindings); err != nil {
		t.Fatalf("count admin role bindings: %v", err)
	}
	if nBindings != 1 {
		t.Fatalf("scopeless admin bindings = %d, want 1", nBindings)
	}

	// The admin holds `**` at global scope: any concrete capability is allowed.
	caps, err := authz.NewSQLAuthorizer(pool).CapabilitiesOnScope(ctx, admin.ID, authz.GlobalScope())
	if err != nil {
		t.Fatalf("CapabilitiesOnScope(admin, global): %v", err)
	}
	if !caps.Allows("anything:goes") {
		t.Fatalf("admin should hold ** at global scope; caps = %v", caps)
	}

	// --- Idempotency: a second run must not error or duplicate anything ---
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("second run: %v", err)
	}

	// Still exactly one user (EnsureAdmin is a no-op when users exist).
	if n, err := q.CountUsers(ctx); err != nil {
		t.Fatalf("CountUsers: %v", err)
	} else if n != 1 {
		t.Fatalf("user count = %d after two runs, want 1", n)
	}

	// SSH CA public material is unchanged (no new key was minted).
	sshRow2, err := q.GetActiveCA(ctx, "ssh")
	if err != nil {
		t.Fatalf("GetActiveCA(ssh) second: %v", err)
	}
	if sshRow2.PublicMaterial != sshRow.PublicMaterial {
		t.Fatalf("ssh CA public material changed across runs")
	}

	// Exactly one active session signing key (Init did not run twice).
	var nKeys int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM session_signing_keys WHERE active`).Scan(&nKeys); err != nil {
		t.Fatalf("count active session keys: %v", err)
	}
	if nKeys != 1 {
		t.Fatalf("active session signing keys = %d, want 1", nKeys)
	}
}

// TestBootstrapSkipMeshCA confirms --skip-mesh-ca omits the mesh files while
// still provisioning the SSH CA and session key.
func TestBootstrapSkipMeshCA(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	out := t.TempDir()

	cfg := config{
		dsn:          dsn,
		masterKeyB64: masterKeyB64,
		outDir:       out,
		skipMeshCA:   true,
	}
	ctx := context.Background()
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(out, "mesh-ca.crt")); !os.IsNotExist(err) {
		t.Fatalf("mesh-ca.crt should not exist with --skip-mesh-ca (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(out, "ssh-ca.pub")); err != nil {
		t.Fatalf("ssh-ca.pub should exist: %v", err)
	}

	pool, err := postgres.NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	q := sqlc.New(pool)

	// No mesh CA row was created.
	if _, err := q.GetActiveCA(ctx, "mesh"); err == nil {
		t.Fatalf("mesh CA should not exist with --skip-mesh-ca")
	} else if err != pgx.ErrNoRows && err.Error() != pgx.ErrNoRows.Error() {
		t.Fatalf("GetActiveCA(mesh) unexpected error: %v", err)
	}
}
