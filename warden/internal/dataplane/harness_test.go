package dataplane_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/gateway"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// testSessionTTL / testGatewayEndpoint are the fixed session-admission params used
// by the mesh test servers.
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
	svc := session.NewService(sqlc.New(pool), authz.NewSQLAuthorizer(pool), sessiontoken.NewMinter(priv), testGatewayEndpoint, testSessionTTL)
	return svc, pub
}

// testMasterKeyB64 is a base64-encoded 32-byte KEK used to build a real sealer
// for the tests, so the sealing write paths are exercised.
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

// createRoleWithCaps creates a role and populates its capabilities from a JSON
// capability array string (e.g. `["ssh:login:deploy","**"]`). It returns the
// new role.
func createRoleWithCaps(t *testing.T, ctx context.Context, q *sqlc.Queries, name string, folderID pgtype.UUID, capsJSON string) sqlc.Role { //nolint:revive
	t.Helper()
	role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: name, FolderID: folderID})
	if err != nil {
		t.Fatalf("createRoleWithCaps: create role %q: %v", name, err)
	}
	var patterns []string
	if err := json.Unmarshal([]byte(capsJSON), &patterns); err != nil {
		t.Fatalf("createRoleWithCaps: unmarshal caps %q: %v", capsJSON, err)
	}
	for _, pat := range patterns {
		sc, ac, qu := authz.NormalizeCap(pat)
		if err := q.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{
			RoleID:    role.ID,
			Scope:     sc,
			Action:    ac,
			Qualifier: qu,
		}); err != nil {
			t.Fatalf("createRoleWithCaps: insert cap %q for role %q: %v", pat, name, err)
		}
	}
	return role
}

// registerMeshServices mounts the mesh service set (Gateway + Dataplane) on the mux,
// mirroring the wiring in main.go / rpc.RegisterMeshServices.
func registerMeshServices(mux *http.ServeMux, pool *pgxpool.Pool, auditLog *audit.Logger, setupSvc *dataplane.SetupService, registry *dataplane.Registry, pubKey ed25519.PublicKey) error {
	authorizer := authz.NewSQLAuthorizer(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	services := rpc.MeshServices{Gateway: gateway.NewHandler(registry, pubKey)}
	if setupSvc != nil {
		services.Dataplane = dataplane.NewHandler(setupSvc, registry, pool, terminator)
	}
	rpc.RegisterMeshServices(mux, services)
	return nil
}
