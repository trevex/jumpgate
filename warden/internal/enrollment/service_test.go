package enrollment_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/enrollment"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// testMasterKeyB64 is a base64-encoded 32-byte KEK for a real test sealer
// (mirrors warden/internal/vault/harness_test.go testSealer).
const testMasterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func newTestSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	key, err := secrets.MasterKeyFromConfig(testMasterKeyB64)
	if err != nil {
		t.Fatalf("test master key: %v", err)
	}
	s, err := secrets.NewSealer(key)
	if err != nil {
		t.Fatalf("test sealer: %v", err)
	}
	return s
}

// newEnrollmentPool starts an ephemeral Postgres, migrates it, and returns a
// connected pool (mirrors warden/internal/authz/sql_authorizer_test.go newPool).
func newEnrollmentPool(t *testing.T) *pgxpool.Pool {
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

// provisionMeshCA seals a fresh mesh CA into ca_keys(kind='mesh', active=true)
// (mirrors warden/cmd/warden-bootstrap/main.go provisionMeshCA).
func provisionMeshCA(t *testing.T, q *sqlc.Queries, sealer *secrets.Sealer) {
	t.Helper()
	ctx := context.Background()
	keyDER, certPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatalf("GenerateMeshCA: %v", err)
	}
	sealed, err := sealer.Seal(keyDER)
	if err != nil {
		t.Fatalf("seal mesh ca: %v", err)
	}
	if _, err := q.CreateCAKey(ctx, sqlc.CreateCAKeyParams{
		Kind: "mesh", Sealed: sealed, PublicMaterial: string(certPEM),
	}); err != nil {
		t.Fatalf("store mesh ca: %v", err)
	}
}

func TestSignAgentCert(t *testing.T) {
	ctx := context.Background()
	pool := newEnrollmentPool(t)
	q := sqlc.New(pool)
	sealer := newTestSealer(t)
	provisionMeshCA(t, q, sealer)

	// An asset to bind the token to.
	f, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "clusters"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: f.ID, Name: "prod-cluster", Labels: []byte("{}"), Kind: "k8s"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	svc := enrollment.NewService(pool, sealer)

	// Mint a token bound to the asset.
	raw, exp, err := svc.Mint(ctx, asset.ID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if raw == "" || !exp.After(time.Now()) {
		t.Fatalf("bad token/exp: %q %v", raw, exp)
	}

	// Agent-side: generate a CSR (key stays local).
	_, csrDER, err := ca.GenerateCSR("spiffe://jumpgate/agent/" + asset.ID.String())
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Exchange token + CSR for a cert.
	certPEM, bundlePEM, err := svc.SignAgentCert(ctx, raw, csrPEM)
	if err != nil {
		t.Fatalf("SignAgentCert: %v", err)
	}

	// The leaf must carry exactly the asset-scoped SPIFFE URI and chain to the CA bundle.
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	want := "spiffe://jumpgate/agent/" + asset.ID.String()
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want {
		t.Fatalf("leaf URIs = %v, want [%s]", leaf.URIs, want)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundlePEM) {
		t.Fatal("no CA in bundle")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}

	// Single-use: the same token cannot be redeemed twice.
	if _, _, err := svc.SignAgentCert(ctx, raw, csrPEM); err == nil {
		t.Fatal("second SignAgentCert must fail (single-use)")
	}

	// Unknown token fails.
	if _, _, err := svc.SignAgentCert(ctx, "not-a-real-token", csrPEM); err == nil {
		t.Fatal("unknown token must fail")
	}
}
