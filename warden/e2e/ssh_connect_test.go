//go:build e2e

// Package e2e holds an opt-in, full-stack integration test for the SSH connect
// path. It is EXCLUDED from the default build and from `make ci` by the `e2e`
// build tag; run it with `make e2e-ssh`.
//
// # What this test proves
//
// It boots the THREE REAL jumpgate binaries as localhost subprocesses —
//
//	warden   (Go)   — control plane: session admission + mesh services
//	gateway  (Rust) — external TLS front door + worker roster + tunnel router
//	ssh-proxy(Rust) — data-plane worker: SSH server + target dial
//
// — wired together over a real, DB-backed mesh PKI, and drives the CLI's real
// connect core (cli/cmd.DialTunnel → the same runConnect the `jumpgate connect`
// command uses) against a target sshd. It asserts that an exec's output and exit
// code round-trip all the way from the target, back through the worker, gateway,
// and tunnel to the client, and that a session.started + session.ended audit
// pair lands in warden's hash-chained audit_log.
//
// The end-to-end wire path exercised:
//
//	CLI runConnect → warden CreateSession (bearer API)      [REAL warden]
//	CLI tunnel.Dial → gateway CONNECT (external TLS)        [REAL gateway]
//	gateway → ssh-proxy (mesh mTLS, SPIFFE pin)             [REAL worker]
//	ssh-proxy → warden SetupSession (mesh mTLS)             [REAL warden]
//	ssh-proxy → target sshd (SSH cert auth over Kw)         [in-test target]
//
// # What is real vs scaled back
//
//   - REAL: warden, gateway, ssh-proxy binaries (subprocesses); the mesh PKI +
//     session/SSH CAs (issued by warden's own ca package + the warden-meshcert
//     bootstrap tool, sealed under VAULT_MASTER_KEY, stored in the same Postgres
//     warden reads at boot); the CLI connect core (DialTunnel wraps runConnect).
//   - SCALED BACK (per the harness's pragmatism allowance, and matching the
//     worker's own proxy_e2e target stub): the TARGET sshd is an in-test
//     golang.org/x/crypto/ssh server rather than a system sshd. It trusts
//     warden's SSH CA, accepts a cert whose principals include the login, and on
//     exec echoes the command back + exit 0. A system sshd would add OS/config
//     flakiness without exercising any more jumpgate code.
//   - SCALED BACK: the final SSH step is an explicit exec run over the REAL
//     tunnel (deterministic output + exit code) rather than cli/cmd.runSession's
//     interactive shell. runConnect (asset resolve + CreateSession + gateway
//     tunnel dial) is driven for real via cli/cmd.DialTunnel.
//
// # Module layout
//
// This test lives in the warden module because it needs warden's internal
// packages (testsupport, migrate, gen, ca, secrets, session, auth) — internal
// packages are importable only within their own module, which rules out a
// separate e2e module. It also imports the CLI's connect core via the exported
// cli/cmd.DialTunnel; that cross-module import is resolved by the repo-root
// go.work workspace (both modules are `use`d). Consequence: `go mod tidy` in the
// warden module cannot run with this package present (tidy resolves imports
// without the workspace and would try to fetch cli as an external module). The
// normal build/test and `make e2e-ssh` are unaffected — they run under go.work.
//
// # Requirements
//
// The Nix devshell tooling must be on PATH: initdb/pg_ctl/createdb (ephemeral
// Postgres), plus the built binaries under ../../target/debug (cargo build) and
// a built warden + warden-meshcert (go build). `make e2e-ssh` builds them first.
// Absent any prerequisite the test t.Skip()s with a precise reason.
package e2e

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
	gossh "golang.org/x/crypto/ssh"

	clicmd "github.com/trevex/jumpgate/cli/cmd"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// Fixed mesh identities. The worker's WORKER_ID must equal the id segment of its
// mesh cert SPIFFE SAN (warden derives the authoritative worker_id from the SAN).
const (
	wardenSpiffe  = "spiffe://jumpgate/warden/warden"
	gatewaySpiffe = "spiffe://jumpgate/gateway/gateway"
	workerID      = "sshproxy1"
	workerSpiffe  = "spiffe://jumpgate/worker/" + workerID

	bootstrapAdminEmail = "admin@e2e.test"
	bootstrapAdminPass  = "admin-password-1234"

	userEmail = "deployer@e2e.test"
	login     = "deploy"
	assetName = "e2e-target"

	execCommand = "jumpgate-ok"
)

// masterKeyB64 is a fixed base64 32-byte VAULT_MASTER_KEY shared by the test's
// direct seeding, the warden-meshcert tool, and the warden subprocess so they
// all unseal the same sealed material.
const masterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestSSHConnectFullStack(t *testing.T) {
	repoRoot := repoRoot(t)
	bins := locateBinaries(t, repoRoot)

	// 1. Ephemeral Postgres + migrations.
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool := newPool(t, dsn)

	sealer := newSealer(t)

	// 1b. Object store for session recordings (real S3-compatible Silo server).
	//     Started before warden/worker so both can be pointed at it via env.
	silo := startSilo(t)

	// 2. Provision CAs + session signing key + mesh CA, all sealed under the same
	//    master key warden will boot with. warden loads the active session key at
	//    boot, so it must exist BEFORE we start warden.
	initSSHCA(t, pool, sealer)
	initMeshCA(t, pool, sealer)
	initSessionKey(t, pool, sealer)

	// 3. Target sshd (in-test x/crypto/ssh). It trusts warden's SSH CA and, on
	//    exec, echoes the command + exits 0.
	sshCAPub := activeSSHCAPublicKey(t, pool)
	targetAddr, targetHostPub := startTargetSSHD(t, sshCAPub)

	// 4. Seed identity/catalog: user + bearer token, role granting ssh:login:deploy
	//    standing-bound to the user on the asset, and the ssh asset config pointing
	//    at the target sshd.
	token, roleBindingID := seedAccess(t, pool, targetAddr, targetHostPub)

	// An admin user for the revocation phase's admin API calls. warden's first-boot
	// bootstrap only seeds an admin when the users table is empty, and seedAccess
	// already created the deployer, so seed the admin directly here.
	seedAdmin(t, pool, bootstrapAdminEmail, bootstrapAdminPass)

	// 5. Mesh certs for warden, gateway (+ its external server cert), and the
	//    worker, all issued by warden-meshcert against the seeded mesh CA.
	certDir := t.TempDir()
	wardenCerts := mintMeshCert(t, bins.meshcert, dsn, wardenSpiffe, filepath.Join(certDir, "warden"))
	gatewayMeshCerts := mintMeshCert(t, bins.meshcert, dsn, gatewaySpiffe, filepath.Join(certDir, "gateway-mesh"))
	gatewayExtCerts := mintMeshCert(t, bins.meshcert, dsn, gatewaySpiffe, filepath.Join(certDir, "gateway-ext"))
	workerCerts := mintMeshCert(t, bins.meshcert, dsn, workerSpiffe, filepath.Join(certDir, "worker"))

	// Reserve loopback ports for the services.
	wardenAPIAddr := reservePort(t)
	wardenMeshAddr := reservePort(t)
	gatewayExtAddr := reservePort(t)
	gatewayHealthAddr := reservePort(t)
	workerDataplaneAddr := reservePort(t)

	// 6. Start warden (real Go binary).
	startProcess(t, "warden", bins.warden, []string{
		"DATABASE_URL=" + dsn,
		"VAULT_MASTER_KEY=" + masterKeyB64,
		"LISTEN_ADDR=" + wardenAPIAddr,
		"MESH_LISTEN_ADDR=" + wardenMeshAddr,
		"MESH_CERT_FILE=" + wardenCerts.cert,
		"MESH_KEY_FILE=" + wardenCerts.key,
		"MESH_CA_FILE=" + wardenCerts.ca,
		"GATEWAY_ENDPOINT=" + gatewayExtAddr,
		"SESSION_TOKEN_TTL=120s",
		"REAPER_INTERVAL=2s",
		"AUTHZ_SWEEP_INTERVAL=2s",
		"AUTHZ_SWEEP_DEBOUNCE=100ms",
		"ORPHAN_GC_INTERVAL=2s",
		"AUDIT_DRAIN_INTERVAL=500ms",
		"BOOTSTRAP_ADMIN_EMAIL=" + bootstrapAdminEmail,
		"BOOTSTRAP_ADMIN_PASSWORD=" + bootstrapAdminPass,
		"RECORDING_BUCKET=" + silo.bucket,
		"RECORDING_S3_ENDPOINT=" + silo.endpoint,
		"RECORDING_S3_REGION=us-east-1",
		"AWS_ACCESS_KEY_ID=" + silo.accessKey,
		"AWS_SECRET_ACCESS_KEY=" + silo.secretKey,
		"LOG_LEVEL=debug",
	})
	waitTCP(t, "warden api", wardenAPIAddr)
	waitTCP(t, "warden mesh", wardenMeshAddr)

	// 7. Start gateway (real Rust binary). Its external server cert is mesh-issued
	//    (URI SAN); the CLI trusts the mesh CA and skips the hostname check.
	startProcess(t, "gateway", bins.gateway, []string{
		"GATEWAY_LISTEN=" + gatewayExtAddr,
		"GATEWAY_HEALTH_LISTEN=" + gatewayHealthAddr,
		"GATEWAY_TLS_CERT=" + gatewayExtCerts.cert,
		"GATEWAY_TLS_KEY=" + gatewayExtCerts.key,
		"GATEWAY_MESH_CERT=" + gatewayMeshCerts.cert,
		"GATEWAY_MESH_KEY=" + gatewayMeshCerts.key,
		"GATEWAY_MESH_CA=" + gatewayMeshCerts.ca,
		"WARDEN_MESH_ADDR=https://" + wardenMeshAddr,
		"WARDEN_MESH_SPIFFE=" + wardenSpiffe,
		"RUST_LOG=info",
	})
	waitTCP(t, "gateway health", gatewayHealthAddr)
	waitTCP(t, "gateway external", gatewayExtAddr)

	// 8. Start ssh-proxy worker (real Rust binary). WORKER_ID must match the SAN
	//    id; WORKER_DATAPLANE_ADDR must be a concrete loopback the gateway dials.
	startProcess(t, "ssh-proxy", bins.sshProxy, []string{
		"WORKER_ID=" + workerID,
		"WORKER_DATAPLANE_ADDR=" + workerDataplaneAddr,
		"WORKER_MESH_CERT=" + workerCerts.cert,
		"WORKER_MESH_KEY=" + workerCerts.key,
		"WORKER_MESH_CA=" + workerCerts.ca,
		"WARDEN_MESH_ADDR=https://" + wardenMeshAddr,
		"WARDEN_SPIFFE=" + wardenSpiffe,
		"GATEWAY_SPIFFE=" + gatewaySpiffe,
		"RECORDING_BUCKET=" + silo.bucket,
		"RECORDING_S3_ENDPOINT=" + silo.endpoint,
		"RECORDING_S3_REGION=us-east-1",
		// The recorder flushes a final (small) part on Finish, so a short exec still
		// produces a complete upload; the default 5 MiB part size never triggers an
		// early flush for these tiny sessions.
		"AWS_ACCESS_KEY_ID=" + silo.accessKey,
		"AWS_SECRET_ACCESS_KEY=" + silo.secretKey,
		"RUST_LOG=info",
	})
	waitTCP(t, "worker dataplane", workerDataplaneAddr)

	// 9. Drive the REAL connect core against the running stack, then run an exec
	//    over the real tunnel and assert the round-trip.
	//
	// wardenAddr/token/caFile mirror the persisted CLI config; caFile is the mesh
	// CA the CLI trusts to verify the gateway's (mesh-issued) external leaf.
	wardenAddr := "http://" + wardenAPIAddr
	caFile := gatewayMeshCerts.ca

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// The worker registers with warden asynchronously and warden pushes it into
	// the gateway roster on its own schedule; until then the gateway has no worker
	// to route to and refuses the tunnel. There is no external observable for
	// roster population (it is in-memory), so retry the full connect with backoff.
	tunnel, signer := dialWithRetry(ctx, t, wardenAddr, token, caFile)
	defer func() { _ = tunnel.Close() }()

	out, code, err := runExec(tunnel, login, signer, execCommand)
	if err != nil {
		t.Fatalf("exec over tunnel: %v", err)
	}
	if !strings.Contains(out, execCommand) {
		t.Fatalf("exec output = %q, want it to contain %q", out, execCommand)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	t.Logf("exec round-trip OK: output=%q code=%d", strings.TrimSpace(out), code)

	// 10. Assert the audit pair. session.started rides SetupSession; session.ended
	//     lands after the worker reports the finished session to warden.
	assertAuditPair(t, pool)

	// 10b. Recording phases (reuse the booted stack, real Silo object store).
	//      The happy-path exec above already produced a required recording; assert
	//      it was uploaded, then cover the exempt and fail-closed cases. These run
	//      BEFORE revocation, which removes the deployer's standing access.
	assertRecordedSession(ctx, t, pool, silo)
	assertExemptSessionNotRecorded(ctx, t, pool, silo, wardenAddr, caFile)
	assertFailClosedWhenRecordingUnavailable(ctx, t, pool, silo, wardenAddr, token, caFile)

	// 11. Revocation phase (reuses the already-booted stack). Open a long-lived
	//     session over a FRESH tunnel, then remove the user's standing role
	//     binding through the real admin API. The control plane's authorization
	//     re-evaluation must detect that the live session is no longer permitted
	//     and force it closed at the worker; the client's channel read then
	//     unblocks with EOF and a session.terminated audit event lands.
	assertRevocationClosesLiveSession(ctx, t, pool, wardenAddr, token, caFile, roleBindingID)
}

// assertRevocationClosesLiveSession opens a held-open shell over a fresh tunnel,
// revokes the standing role binding via the admin AccessService RPC, and asserts
// the live session is torn down end-to-end: the held channel closes and a
// session.terminated audit event is recorded within a bounded deadline.
func assertRevocationClosesLiveSession(ctx context.Context, t *testing.T, pool *pgxpool.Pool, wardenAddr, token, caFile, roleBindingID string) {
	t.Helper()

	// Establish a fresh tunnel and hold a shell open. The returned channel is
	// closed by the reader goroutine when the session channel reaches EOF.
	tunnel, signer := dialWithRetry(ctx, t, wardenAddr, token, caFile)
	defer func() { _ = tunnel.Close() }()

	client, closed, err := openHeldSession(tunnel, login, signer)
	if err != nil {
		t.Fatalf("open held session: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The session must still be live just after opening (not already torn down).
	select {
	case <-closed:
		t.Fatalf("held session closed before revocation")
	case <-time.After(500 * time.Millisecond):
	}

	// Revoke the standing binding via the real admin API.
	adminTok := adminLogin(ctx, t, wardenAddr)
	deleteRoleBinding(ctx, t, wardenAddr, adminTok, roleBindingID)
	t.Logf("deleted role binding %s via admin API", roleBindingID)

	// The held session's channel must close (worker force-close) AND a
	// session.terminated audit event must land, both within the deadline.
	deadline := time.Now().Add(20 * time.Second)
	channelClosed := false
	for {
		if !channelClosed {
			select {
			case <-closed:
				channelClosed = true
				t.Logf("held session channel closed (worker force-close)")
			default:
			}
		}
		if channelClosed && auditCount(t, pool, "session.terminated") >= 1 {
			t.Logf("revocation cascade complete: session.terminated audit present")
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("revocation did not close the live session in time: channelClosed=%v session.terminated=%d",
				channelClosed, auditCount(t, pool, "session.terminated"))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// adminLogin logs in as the bootstrap admin via the AuthService RPC and returns
// the resulting bearer token.
func adminLogin(ctx context.Context, t *testing.T, wardenAddr string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, wardenAddr)
	resp, err := c.Login(ctx, connect.NewRequest(&authv1.LoginRequest{
		Email:    bootstrapAdminEmail,
		Password: bootstrapAdminPass,
	}))
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	if resp.Msg.Token == "" {
		t.Fatalf("admin login returned empty token")
	}
	return resp.Msg.Token
}

// deleteRoleBinding removes a role binding through the admin AccessService RPC,
// attaching the admin bearer token.
func deleteRoleBinding(ctx context.Context, t *testing.T, wardenAddr, adminTok, roleBindingID string) {
	t.Helper()
	c := accessv1connect.NewAccessServiceClient(http.DefaultClient, wardenAddr)
	req := connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: roleBindingID})
	req.Header().Set("Authorization", "Bearer "+adminTok)
	if _, err := c.DeleteRoleBinding(ctx, req); err != nil {
		t.Fatalf("DeleteRoleBinding: %v", err)
	}
}

// --- CA + key provisioning (direct DB seeding, sealed under the master key) ---

func newSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	key, err := secrets.MasterKeyFromConfig(masterKeyB64)
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	s, err := secrets.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func initSSHCA(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) {
	t.Helper()
	seed, line, err := ca.GenerateSSHCA()
	if err != nil {
		t.Fatalf("GenerateSSHCA: %v", err)
	}
	sealed, err := sealer.Seal(seed)
	if err != nil {
		t.Fatalf("seal ssh ca: %v", err)
	}
	if _, err := gen.New(pool).CreateCAKey(context.Background(), gen.CreateCAKeyParams{
		Kind: "ssh", Sealed: sealed, PublicMaterial: line,
	}); err != nil {
		t.Fatalf("store ssh ca: %v", err)
	}
}

func initMeshCA(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) {
	t.Helper()
	keyDER, certPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatalf("GenerateMeshCA: %v", err)
	}
	sealed, err := sealer.Seal(keyDER)
	if err != nil {
		t.Fatalf("seal mesh ca: %v", err)
	}
	if _, err := gen.New(pool).CreateCAKey(context.Background(), gen.CreateCAKeyParams{
		Kind: "mesh", Sealed: sealed, PublicMaterial: string(certPEM),
	}); err != nil {
		t.Fatalf("store mesh ca: %v", err)
	}
}

func initSessionKey(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) {
	t.Helper()
	if err := session.NewKeyStore(gen.New(pool), sealer).Init(context.Background()); err != nil {
		t.Fatalf("init session signing key: %v", err)
	}
}

// activeSSHCAPublicKey returns the active SSH CA's authorized_keys public line
// as a parsed ssh.PublicKey, so the target sshd can trust certs it signs.
func activeSSHCAPublicKey(t *testing.T, pool *pgxpool.Pool) gossh.PublicKey {
	t.Helper()
	row, err := gen.New(pool).GetActiveCA(context.Background(), "ssh")
	if err != nil {
		t.Fatalf("GetActiveCA(ssh): %v", err)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(row.PublicMaterial))
	if err != nil {
		t.Fatalf("parse ssh ca public line: %v", err)
	}
	return pub
}

// --- Identity/catalog seeding ------------------------------------------------

// seedAccess creates a user + bearer token, a role carrying ssh:login:<login>
// standing-bound to the user on the asset, and the ssh asset config pointing at
// the target sshd. Returns the bearer token for the CLI config and the id of the
// created role binding (so a caller can later revoke it via the admin API).
func seedAccess(t *testing.T, pool *pgxpool.Pool, targetAddr, targetHostPub string) (token, roleBindingID string) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: userEmail, DisplayName: "Deployer"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{
		FolderID: folder.ID, Name: assetName, Labels: []byte("{}"), Kind: "ssh",
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID:       asset.ID,
		HostPublicKey: targetHostPub,
		TargetAddress: targetAddr,
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: login, Kind: "ca",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}

	role, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "ssh-deploy", Capabilities: capsJSON("ssh:login:" + login),
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	rb, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeAssetID:  pgUUID(asset.ID),
		SubjectUserID: pgUUID(user.ID),
	})
	if err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	tok, err := auth.NewTokenService(q).Issue(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("issue bearer token: %v", err)
	}
	return tok, rb.ID.String()
}

// seedAdmin creates an admin user with a password login, used by the revocation
// phase to authenticate against warden's admin API.
func seedAdmin(t *testing.T, pool *pgxpool.Pool, email, password string) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash admin password: %v", err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatalf("set admin password: %v", err)
	}
	// Mirror bootstrap.EnsureAdmin: the admin holds `**` globally via a scopeless
	// standing binding so the capability-gated management handlers (e.g. RevokeGrant)
	// admit it. There is no is_admin boolean anymore; authz is capability-only.
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "admin-" + uuid.NewString(), Capabilities: []byte(`["**"]`)})
	if err != nil {
		t.Fatalf("create admin role: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        role.ID,
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatalf("bind admin role: %v", err)
	}
}

// --- Target sshd (in-test) ---------------------------------------------------

// startTargetSSHD binds an in-test x/crypto/ssh server that trusts the given SSH
// CA, accepts a cert whose principals include the login, and on exec echoes the
// command back then exits 0. Returns its address and its host public key line.
func startTargetSSHD(t *testing.T, caPub gossh.PublicKey) (addr, hostPubLine string) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("target host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("target host signer: %v", err)
	}

	checker := &gossh.CertChecker{
		IsUserAuthority: func(k gossh.PublicKey) bool {
			return string(k.Marshal()) == string(caPub.Marshal())
		},
	}

	cfg := &gossh.ServerConfig{
		PublicKeyCallback: checker.Authenticate,
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTarget(conn, cfg)
		}
	}()

	hostPubLine = strings.TrimSpace(string(gossh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	return ln.Addr().String(), hostPubLine
}

// serveTarget handles one accepted target connection: SSH handshake, then for
// each session channel it echoes an exec command back and exits 0.
func serveTarget(conn net.Conn, cfg *gossh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	go gossh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go handleTargetSession(ch, chReqs)
	}
}

func handleTargetSession(ch gossh.Channel, reqs <-chan *gossh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			// The payload is a length-prefixed command string; echo it back.
			var payload struct{ Command string }
			cmd := ""
			if err := gossh.Unmarshal(req.Payload, &payload); err == nil {
				cmd = payload.Command
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = ch.Write([]byte(cmd))
			sendExit(ch, 0)
			_ = ch.Close()
			return
		case "shell":
			// An interactive shell: acknowledge and hold the channel open. We do
			// NOT send exit-status or close the channel — the channel stays open
			// until the far end (the worker) force-closes it. Discard anything the
			// client sends so the reader drains until the channel is torn down.
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() { _, _ = io.Copy(io.Discard, ch) }()
			return
		case "pty-req":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func sendExit(ch gossh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{code}))
}

// --- Client-side exec over the real tunnel -----------------------------------

// runExec runs a single exec over the already-established tunnel, mirroring the
// SSH client cli/cmd.runSession builds but using exec (deterministic output +
// exit code) instead of an interactive shell.
func runExec(tunnel net.Conn, login string, signer gossh.Signer, cmd string) (string, int, error) {
	cfg := &gossh.ClientConfig{
		User:            login,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // the tunnel is already mutually authenticated to the worker (mesh mTLS); mirrors the CLI's sshclient
		Timeout:         15 * time.Second,
	}
	clientConn, chans, reqs, err := gossh.NewClientConn(tunnel, "jumpgate", cfg)
	if err != nil {
		return "", 0, fmt.Errorf("client handshake: %w", err)
	}
	client := gossh.NewClient(clientConn, chans, reqs)
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	out, err := sess.Output(cmd)
	if err != nil {
		var exitErr *gossh.ExitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr.ExitStatus(), nil
		}
		return string(out), 0, fmt.Errorf("exec: %w", err)
	}
	return string(out), 0, nil
}

// openHeldSession performs the SSH client handshake over an established tunnel
// and opens a long-lived shell session that stays open until the far end tears
// it down. It returns the live client (the caller closes it) and a channel that
// is closed once the session's stdout reaches EOF — which happens when the
// worker force-closes the session on teardown.
func openHeldSession(tunnel net.Conn, login string, signer gossh.Signer) (*gossh.Client, <-chan struct{}, error) {
	cfg := &gossh.ClientConfig{
		User:            login,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // the tunnel is already mutually authenticated to the worker (mesh mTLS); mirrors the CLI's sshclient
		Timeout:         15 * time.Second,
	}
	clientConn, chans, reqs, err := gossh.NewClientConn(tunnel, "jumpgate", cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("client handshake: %w", err)
	}
	client := gossh.NewClient(clientConn, chans, reqs)

	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("new session: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := sess.Shell(); err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("start shell: %w", err)
	}

	// The read blocks while the session is live and unblocks (EOF) when the
	// worker force-closes the channel on teardown; signal that via closed.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_, _ = io.Copy(io.Discard, stdout)
	}()
	return client, closed, nil
}

// --- Audit assertions --------------------------------------------------------

func assertAuditPair(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		started := auditCount(t, pool, "session.started")
		ended := auditCount(t, pool, "session.ended")
		if started >= 1 && ended >= 1 {
			t.Logf("audit pair present: session.started=%d session.ended=%d", started, ended)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit pair not found in time: session.started=%d session.ended=%d", started, ended)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func auditCount(t *testing.T, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event_type = $1`, eventType).Scan(&n); err != nil {
		t.Fatalf("count audit %s: %v", eventType, err)
	}
	return n
}

// --- Process orchestration ---------------------------------------------------

// startProcess launches a subprocess with the given extra environment, streams
// its stderr/stdout into a buffer dumped to t.Log on failure, and kills it on
// cleanup.
func startProcess(t *testing.T, name, bin string, extraEnv []string) {
	t.Helper()
	cmd := exec.Command(bin) // #nosec G204 -- fixed, test-built binary paths
	cmd.Env = append(os.Environ(), extraEnv...)

	var mu sync.Mutex
	var buf strings.Builder
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("%s pipe: %v", name, err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	_ = pw.Close()

	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			mu.Lock()
			buf.WriteString(sc.Text())
			buf.WriteByte('\n')
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			mu.Lock()
			logs := buf.String()
			mu.Unlock()
			t.Logf("=== %s logs ===\n%s", name, logs)
		}
	})
}

// --- Mesh cert minting via the warden-meshcert bootstrap tool ----------------

type meshCert struct {
	cert string
	key  string
	ca   string
}

func mintMeshCert(t *testing.T, meshcertBin, dsn, spiffe, outDir string) meshCert {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}
	cmd := exec.Command(meshcertBin, "-spiffe", spiffe, "-out", outDir) // #nosec G204 -- fixed tool path + literal flags
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+dsn,
		"VAULT_MASTER_KEY="+masterKeyB64,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("warden-meshcert %s: %v\n%s", spiffe, err, out)
	}
	return meshCert{
		cert: filepath.Join(outDir, "cert.pem"),
		key:  filepath.Join(outDir, "key.pem"),
		ca:   filepath.Join(outDir, "ca-bundle.pem"),
	}
}

// --- Binary location ---------------------------------------------------------

type binaries struct {
	warden   string
	meshcert string
	gateway  string
	sshProxy string
}

func locateBinaries(t *testing.T, repoRoot string) binaries {
	t.Helper()

	// Go binaries: build them into a temp dir so we run exactly this tree's code.
	goBin := t.TempDir()
	wardenBin := filepath.Join(goBin, "warden")
	meshcertBin := filepath.Join(goBin, "warden-meshcert")
	goBuild(t, repoRoot, wardenBin, "github.com/trevex/jumpgate/warden/cmd/warden")
	goBuild(t, repoRoot, meshcertBin, "github.com/trevex/jumpgate/warden/cmd/warden-meshcert")

	// Rust binaries: expect a prior `cargo build` (make e2e-ssh does it).
	gatewayBin := filepath.Join(repoRoot, "target", "debug", "gateway")
	sshProxyBin := filepath.Join(repoRoot, "target", "debug", "ssh-proxy")
	for _, b := range []string{gatewayBin, sshProxyBin} {
		if _, err := os.Stat(b); err != nil {
			t.Skipf("rust binary missing (%s); run `cargo build --workspace` or `make e2e-ssh`", b)
		}
	}

	return binaries{warden: wardenBin, meshcert: meshcertBin, gateway: gatewayBin, sshProxy: sshProxyBin}
}

func goBuild(t *testing.T, repoRoot, outPath, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", outPath, pkg) // #nosec G204 -- fixed args
	cmd.Dir = filepath.Join(repoRoot, "warden")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
	}
}

// repoRoot resolves the repository root from this test file's directory
// (warden/e2e → ../..).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// wd is .../warden/e2e
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repo root not found at %s (no go.work): %v", root, err)
	}
	return root
}

// --- Readiness + small helpers -----------------------------------------------

// reservePort binds an ephemeral loopback port, closes it, and returns the
// address string. There is a small race between release and reuse, but it is
// acceptable for a localhost test and lets us pass concrete addresses to the
// subprocesses (the worker advertises its exact dataplane address).
func reservePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitTCP polls until a TCP dial to addr succeeds or the deadline elapses.
func waitTCP(t *testing.T, name, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not reachable at %s in time: %v", name, addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// dialWithRetry drives the real connect core (DialTunnel → runConnect) until it
// succeeds or ctx expires, retrying while the gateway roster is still empty. It
// returns the live tunnel and the client signer on success.
func dialWithRetry(ctx context.Context, t *testing.T, wardenAddr, token, caFile string) (net.Conn, gossh.Signer) {
	t.Helper()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("connect never succeeded before deadline: %v", lastErr)
		default:
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		tunnel, signer, err := clicmd.DialTunnel(attemptCtx, wardenAddr, token, caFile, login, assetName)
		cancel()
		if err == nil {
			return tunnel, signer
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
}

func newPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func capsJSON(xs ...string) []byte { b, _ := json.Marshal(xs); return b }

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
