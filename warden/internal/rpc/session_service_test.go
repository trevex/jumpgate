package rpc_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/ssh"

	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// seedSSHAsset creates a folder + ssh asset with a config row plus one ca login
// per given name, and returns the asset id.
func seedSSHAsset(t *testing.T, q *sqlc.Queries, allowedLogins []string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-sess"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg-sess", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, sqlc.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.9:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	for _, login := range allowedLogins {
		if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{
			AssetID: asset.ID, Login: login, Kind: "ca", SecretID: pgtype.UUID{},
		}); err != nil {
			t.Fatalf("UpsertSSHAssetLogin: %v", err)
		}
	}
	return asset.ID
}

// clientSSHKey generates an ephemeral Ed25519 SSH key and returns its wire-form
// public key bytes plus the FingerprintSHA256 the server will bind into the token.
func clientSSHKey(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	return sshPub.Marshal(), ssh.FingerprintSHA256(sshPub)
}

func TestCreateSessionEntitled(t *testing.T) {
	pool, url, signPub := newServerWithSession(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	assetID := seedSSHAsset(t, q, []string{"deploy"})

	// A role that confers the ssh:login:deploy capability, bound to the caller on
	// the asset via a standing role_binding.
	role := createRoleWithCaps(t, ctx, q, "deployer", pgtype.UUID{}, `["ssh:login:deploy"]`)

	seedUser(t, pool, "user@sess", "password123", false)
	var uid uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", "user@sess").Scan(&uid); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgU(assetID), SubjectUserID: pgU(uid),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	pubBytes, wantFP := clientSSHKey(t)
	tok := authClient(t, url, "user@sess", "password123")

	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)
	resp, err := client.CreateSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateSessionRequest{
		AssetId: assetID.String(), ClientSshPublicKey: pubBytes,
	}), tok))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if resp.Msg.SessionToken == "" {
		t.Fatal("empty session_token")
	}
	if resp.Msg.GatewayEndpoint != testGatewayEndpoint {
		t.Fatalf("gateway_endpoint = %q, want %q", resp.Msg.GatewayEndpoint, testGatewayEndpoint)
	}
	if resp.Msg.ExpiresAt == nil {
		t.Fatal("nil expires_at")
	}

	// The minted token must verify against the harness signing public key and carry
	// the caller/asset/proto=ssh + the client-key fingerprint binding.
	claims, err := sessiontoken.NewVerifier(signPub).Verify(resp.Msg.SessionToken)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.UserID != uid {
		t.Fatalf("token user = %s, want %s", claims.UserID, uid)
	}
	if claims.AssetID != assetID {
		t.Fatalf("token asset = %s, want %s", claims.AssetID, assetID)
	}
	if claims.Protocol != "ssh" {
		t.Fatalf("token proto = %q, want ssh", claims.Protocol)
	}
	if claims.ClientKeyFingerprint != wantFP {
		t.Fatalf("token cnf = %q, want %q", claims.ClientKeyFingerprint, wantFP)
	}
}

func TestCreateSessionNoLoginIsNotFound(t *testing.T) {
	pool, url, _ := newServerWithSession(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	// Asset exists and is ssh, but the caller holds no ssh:login:deploy capability.
	assetID := seedSSHAsset(t, q, []string{"deploy"})
	seedUser(t, pool, "nologin@sess", "password123", false)
	pubBytes, _ := clientSSHKey(t)
	tok := authClient(t, url, "nologin@sess", "password123")

	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)
	_, err := client.CreateSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateSessionRequest{
		AssetId: assetID.String(), ClientSshPublicKey: pubBytes,
	}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("no-login CreateSession = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestCreateSessionMissingAssetIsNotFound(t *testing.T) {
	pool, url, _ := newServerWithSession(t)
	ctx := context.Background()

	seedUser(t, pool, "user2@sess", "password123", false)
	pubBytes, _ := clientSSHKey(t)
	tok := authClient(t, url, "user2@sess", "password123")

	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)
	_, err := client.CreateSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateSessionRequest{
		AssetId: uuid.NewString(), ClientSshPublicKey: pubBytes,
	}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing-asset CreateSession = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestCreateWebSession(t *testing.T) {
	pool, url, signPub := newServerWithSession(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	assetID := seedSSHAsset(t, q, []string{"deploy"})

	role := createRoleWithCaps(t, ctx, q, "web-deployer", pgtype.UUID{}, `["ssh:login:deploy"]`)

	seedUser(t, pool, "webuser@sess", "password123", false)
	var uid uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", "webuser@sess").Scan(&uid); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgU(assetID), SubjectUserID: pgU(uid),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	tok := authClient(t, url, "webuser@sess", "password123")
	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)

	resp, err := client.CreateWebSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateWebSessionRequest{
		AssetId: assetID.String(), Login: "deploy",
	}), tok))
	if err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	if resp.Msg.Ticket == "" {
		t.Fatal("empty ticket")
	}
	if resp.Msg.GatewayEndpoint != testGatewayEndpoint {
		t.Fatalf("gateway_endpoint = %q, want %q", resp.Msg.GatewayEndpoint, testGatewayEndpoint)
	}
	if resp.Msg.ExpiresAt == nil {
		t.Fatal("nil expires_at")
	}
	// A web ticket is short-lived (webTTL ≈ 60s).
	if d := time.Until(resp.Msg.ExpiresAt.AsTime()); d <= 0 || d > 90*time.Second {
		t.Fatalf("expires_at delta = %v, want a short positive window", d)
	}

	claims, err := sessiontoken.NewVerifier(signPub).Verify(resp.Msg.Ticket)
	if err != nil {
		t.Fatalf("verify ticket: %v", err)
	}
	if claims.Mode != "web" {
		t.Fatalf("token mode = %q, want web", claims.Mode)
	}
	if claims.Login != "deploy" {
		t.Fatalf("token login = %q, want deploy", claims.Login)
	}
	if claims.ClientKeyFingerprint != "" {
		t.Fatalf("token cnf = %q, want empty for web", claims.ClientKeyFingerprint)
	}
	if claims.UserID != uid {
		t.Fatalf("token user = %s, want %s", claims.UserID, uid)
	}
	if claims.AssetID != assetID {
		t.Fatalf("token asset = %s, want %s", claims.AssetID, assetID)
	}
	if claims.Protocol != "ssh" {
		t.Fatalf("token proto = %q, want ssh", claims.Protocol)
	}
}

func TestCreateWebSessionUnentitledLoginDenied(t *testing.T) {
	pool, url, _ := newServerWithSession(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	// The asset offers "deploy" and "root"; the caller is entitled only to
	// "deploy", so requesting "root" must be denied.
	assetID := seedSSHAsset(t, q, []string{"deploy", "root"})
	role := createRoleWithCaps(t, ctx, q, "web-deploy-only", pgtype.UUID{}, `["ssh:login:deploy"]`)
	seedUser(t, pool, "webdeny@sess", "password123", false)
	var uid uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", "webdeny@sess").Scan(&uid); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgU(assetID), SubjectUserID: pgU(uid),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	tok := authClient(t, url, "webdeny@sess", "password123")
	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)

	_, err := client.CreateWebSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateWebSessionRequest{
		AssetId: assetID.String(), Login: "root",
	}), tok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unentitled-login CreateWebSession = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestCreateSessionUnauthenticated(t *testing.T) {
	_, url, _ := newServerWithSession(t)
	ctx := context.Background()
	pubBytes, _ := clientSSHKey(t)

	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)
	_, err := client.CreateSession(ctx, connect.NewRequest(&sessionv1.CreateSessionRequest{
		AssetId: uuid.NewString(), ClientSshPublicKey: pubBytes,
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon CreateSession = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
