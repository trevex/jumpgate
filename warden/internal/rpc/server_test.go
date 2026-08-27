package rpc_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// testSessionTTL / testGatewayEndpoint are the fixed session-admission params used
// by the rpc test servers.
const (
	testSessionTTL      = 60 * time.Second
	testGatewayEndpoint = "gateway.test:8443"
)

// testSessionService initializes an active session signing key (via a KeyStore
// backed by the test sealer) and builds a session.Service over the pool. It
// returns the service plus the Ed25519 public key so tests can build a
// sessiontoken.Verifier and assert round-tripped claims.
func testSessionService(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) (*session.Service, ed25519.PublicKey) {
	t.Helper()
	ctx := context.Background()
	ks := session.NewKeyStore(sqlc.New(pool), sealer)
	if err := ks.Init(ctx); err != nil {
		t.Fatalf("session keystore init: %v", err)
	}
	priv, pub, err := ks.LoadActive(ctx)
	if err != nil {
		t.Fatalf("session keystore load: %v", err)
	}
	svc := session.NewService(sqlc.New(pool), authz.New(pool), sessiontoken.NewMinter(priv), testGatewayEndpoint, "", false, testSessionTTL)
	return svc, pub
}

// testMasterKeyB64 is a base64-encoded 32-byte KEK used to build a real sealer
// for the rpc tests, so VaultService's sealing write paths are exercised.
const testMasterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// testSealer builds the shared test sealer from testMasterKeyB64.
func testSealer(t *testing.T) *secrets.Sealer {
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

// testAccessRequestService builds a shared access-request Service for the rpc test
// servers (mirrors the wiring in main.go / rpc.Register).
func testAccessRequestService(pool *pgxpool.Pool) *accessrequest.Service {
	return accessrequest.NewService(
		pool,
		audit.New(pool),
		approvals.New(pool),
		authz.NewRoleResolver(pool),
		accessrequest.NoopTerminator{},
		8*time.Hour,
	)
}

func TestMuxServesHealthzAndRegisters(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	mux := http.NewServeMux()
	mux.Handle("/", httpapi.NewRouter(pool))
	if err := registerServices(mux, pool, testAccessRequestService(pool), testSealer(t), audit.New(pool), nil, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}
