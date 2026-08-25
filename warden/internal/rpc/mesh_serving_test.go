package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// meshServingHarness bundles the pieces a mesh-serving test drives: the pool, the
// mesh test CA (to mint client certs), the mTLS server URL, and a freshly-minted
// session admission token bound to a client SSH key (usable by SetupSession).
type meshServingHarness struct {
	pool      *pgxpool.Pool
	mca       *meshTestCA
	url       string
	token     string
	clientPub []byte // authorized_keys form of the client's ephemeral key (Kc)
	workerPub []byte // authorized_keys form of the worker's per-session key (Kw)
	subject   uuid.UUID
	asset     uuid.UUID
}

// newMeshServingServer stands up warden's mesh server (Dataplane + Gateway behind
// mesh.Middleware over real mTLS) with a real SetupService, seeds an ssh asset +
// role + active JIT grant, and mints a session admission token for the subject.
func newMeshServingServer(t *testing.T) *meshServingHarness {
	t.Helper()
	ctx := context.Background()

	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := gen.New(pool)

	sealer := testSealer(t)

	// Active session signing key → minter (session svc) + verifier (setup svc).
	ks := session.NewKeyStore(gen.New(pool), sealer)
	if err := ks.Init(ctx); err != nil {
		t.Fatalf("keystore init: %v", err)
	}
	priv, pub, err := ks.LoadActive(ctx)
	if err != nil {
		t.Fatalf("keystore load: %v", err)
	}
	minter := sessiontoken.NewMinter(priv)
	verifier := sessiontoken.NewVerifier(pub)

	// SSH CA (sealed seed) so the broker can mint certs on SetupSession.
	seed, line, err := ca.GenerateSSHCA()
	if err != nil {
		t.Fatalf("GenerateSSHCA: %v", err)
	}
	sealedSeed, err := sealer.Seal(seed)
	if err != nil {
		t.Fatalf("seal ca seed: %v", err)
	}
	if _, err := q.CreateCAKey(ctx, gen.CreateCAKeyParams{Kind: "ssh", Sealed: sealedSeed, PublicMaterial: line}); err != nil {
		t.Fatalf("CreateCAKey: %v", err)
	}

	authorizer := authz.NewSQLAuthorizer(pool)
	auditLog := audit.New(pool)
	broker := vault.NewBroker(pool, sealer, authorizer, auditLog)
	sessionSvc := session.NewService(gen.New(pool), authorizer, minter, testGatewayEndpoint, time.Minute)
	setupSvc := dataplane.NewSetupService(pool, verifier, authorizer, broker, auditLog, time.Hour)

	registry := dataplane.NewRegistry()

	// --- Seed: subject, ssh asset (target set), role, ACTIVE JIT grant (sole login). ---
	subject, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "mesh-subject@e2e", DisplayName: "Subject"})
	if err != nil {
		t.Fatalf("CreateUser subject: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod-mesh-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg-mesh", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, gen.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.7:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "deploy", Kind: "ca", SecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}
	role := createRoleWithCaps(t, ctx, q, "ssh-deploy-mesh-"+uuid.NewString(), pgtype.UUID{}, `["ssh:login:deploy"]`)
	req, err := q.CreateAccessRequest(ctx, gen.CreateAccessRequestParams{
		RequesterUserID:   subject.ID,
		RoleID:            role.ID,
		AssetID:           asset.ID,
		Reason:            "mesh-seed",
		RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		RequiredApprovals: 0,
		GrantedDuration:   pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		Status:            "granted",
	})
	if err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	if _, err := q.CreateAccessGrant(ctx, gen.CreateAccessGrantParams{
		RequestID: req.ID, RoleID: role.ID, ScopeAssetID: asset.ID, SubjectUserID: subject.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}

	// Client ephemeral SSH keypair (bound into the token + presented at SetupSession).
	_, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	cpub, err := ssh.NewPublicKey(cpriv.Public())
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	clientPub := ssh.MarshalAuthorizedKey(cpub)

	// Worker per-session SSH keypair (Kw) — distinct from the client key; certified
	// for the target hop by SetupSession.
	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen worker key: %v", err)
	}
	wpub, err := ssh.NewPublicKey(wpriv.Public())
	if err != nil {
		t.Fatalf("ssh worker pub: %v", err)
	}
	workerPub := ssh.MarshalAuthorizedKey(wpub)

	// Mint the admission token in-process (CreateSession authorizes + binds cnf).
	created, err := sessionSvc.CreateSession(ctx, subject.ID, asset.ID, ssh.FingerprintSHA256(cpub))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// --- Mesh mTLS server: Dataplane + Gateway behind mesh.Middleware. ---
	mca := newMeshTestCA(t)
	serverCertPEM, serverKeyPEM, _ := mca.mint(t, "spiffe://jumpgate/warden/w")
	serverTLS, err := mesh.ServerTLSConfig(serverCertPEM, serverKeyPEM, mca.bundle)
	if err != nil {
		t.Fatalf("server TLS config: %v", err)
	}
	serverTLS.NextProtos = []string{"h2", "http/1.1"}

	mux := http.NewServeMux()
	if err := registerMeshServices(mux, pool, auditLog, setupSvc, registry, pub); err != nil {
		t.Fatalf("register mesh: %v", err)
	}
	srv := httptest.NewUnstartedServer(mesh.Middleware(mux))
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &meshServingHarness{
		pool: pool, mca: mca, url: srv.URL, token: created.Token,
		clientPub: clientPub, workerPub: workerPub, subject: subject.ID, asset: asset.ID,
	}
}

// meshDataplaneClient builds an mTLS Dataplane client identified by the given spiffe.
func meshDataplaneClient(t *testing.T, m *meshTestCA, url, spiffe string) dataplanev1connect.DataplaneServiceClient {
	t.Helper()
	_, _, clientCert := m.mint(t, spiffe)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      m.certPool,
			NextProtos:   []string{"h2"},
			// Mesh leaves carry only URI SANs, so default hostname verification against
			// 127.0.0.1 fails; verify the chain against the mesh CA ourselves.
			InsecureSkipVerify: true, //nolint:gosec // custom chain verification below; hostname check intentionally bypassed for URI-SAN mesh certs
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no server certificate")
				}
				opts := x509.VerifyOptions{Roots: m.certPool, Intermediates: x509.NewCertPool()}
				for _, inter := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(inter)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		},
		ForceAttemptHTTP2: true,
	}
	return dataplanev1connect.NewDataplaneServiceClient(&http.Client{Transport: transport}, url)
}

// TestMeshSetupSessionCertIdentityMatches: a worker cert SAN spiffe://.../worker/w1
// calling SetupSession{worker_id:"w1"} succeeds and records a live_sessions row.
func TestMeshSetupSessionCertIdentityMatches(t *testing.T) {
	h := newMeshServingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := meshDataplaneClient(t, h.mca, h.url, "spiffe://jumpgate/worker/w1")
	resp, err := client.SetupSession(ctx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken: h.token, WorkerId: "w1", Login: "deploy", ClientSshPublicKey: h.clientPub, TargetPublicKey: h.workerPub,
	}))
	if err != nil {
		t.Fatalf("SetupSession: %v", err)
	}
	if resp.Msg.TargetAddress != "10.0.0.7:22" {
		t.Fatalf("TargetAddress = %q, want 10.0.0.7:22", resp.Msg.TargetAddress)
	}
	if resp.Msg.SessionId == "" {
		t.Fatal("expected a non-empty session id")
	}
	// A live session row must now exist for the subject/asset (worker "w1").
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM live_sessions WHERE user_id = $1 AND asset_id = $2 AND worker_id = 'w1'`, h.subject, h.asset).Scan(&n); err != nil {
		t.Fatalf("count live_sessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("live_sessions row count = %d, want 1", n)
	}
}

// TestMeshSetupSessionCertIdentityMismatch: the w1 cert claiming worker_id:"w2" is
// PermissionDenied (the request must not claim a worker other than its cert).
func TestMeshSetupSessionCertIdentityMismatch(t *testing.T) {
	h := newMeshServingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := meshDataplaneClient(t, h.mca, h.url, "spiffe://jumpgate/worker/w1")
	_, err := client.SetupSession(ctx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken: h.token, WorkerId: "w2", Login: "deploy", ClientSshPublicKey: h.clientPub, TargetPublicKey: h.workerPub,
	}))
	assertPermissionDenied(t, err)
}

// TestMeshSetupSessionGatewayRoleDenied: a gateway-role cert may not SetupSession.
func TestMeshSetupSessionGatewayRoleDenied(t *testing.T) {
	h := newMeshServingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := meshDataplaneClient(t, h.mca, h.url, "spiffe://jumpgate/gateway/g1")
	_, err := client.SetupSession(ctx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken: h.token, WorkerId: "g1", Login: "deploy", ClientSshPublicKey: h.clientPub, TargetPublicKey: h.workerPub,
	}))
	assertPermissionDenied(t, err)
}
