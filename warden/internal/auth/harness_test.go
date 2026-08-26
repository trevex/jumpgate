package auth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/access"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/gateway"
	"github.com/trevex/jumpgate/warden/internal/identity"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/recording"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// testSessionTTL / testGatewayEndpoint are the fixed session-admission params used
// by the test servers.
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
// for the tests, so VaultService's sealing write paths are exercised.
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

// testAccessRequestService builds a shared access-request Service for the test
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

// fakePresigner is a test presigner that returns a canned URL and a fixed
// expiry offset from now, recording the last object key it was asked to sign.
type fakePresigner struct{ lastKey string }

func (f *fakePresigner) PresignGet(_ context.Context, objectKey string, ttl time.Duration) (string, time.Time, error) {
	f.lastKey = objectKey
	return "https://recordings.test/get?key=" + objectKey, time.Now().Add(ttl), nil
}

// createRoleWithCaps creates a role and populates its capabilities from a JSON
// capability array string (e.g. `["ssh:login:deploy","**"]`). It returns the
// new role. Tests that previously called q.CreateRole with a Capabilities field
// should use this instead.
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

func testUserServices(pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) rpc.UserServices {
	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}
	authorizer := authz.NewSQLAuthorizer(pool)
	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	services := rpc.UserServices{
		Lookup:        lookup,
		Auth:          auth.NewHandler(q, tokens, authorizer, cookieSecure),
		Identity:      identity.NewHandler(identity.NewService(pool, arSvc, terminator, authorizer), apiguard.New(authorizer, q)),
		Catalog:       catalog.NewHandler(catalog.NewService(pool, sealer, terminator, authorizer, arSvc), apiguard.New(authorizer, q)),
		Access:        access.NewHandler(access.NewService(pool, roles, authorizer, arSvc, arSvc), apiguard.New(authorizer, q)),
		AccessRequest: accessrequest.NewHandler(resolver, arSvc, authorizer, q),
		Vault:         vault.NewHandler(q, sealer, authorizer),
		Recording:     recording.NewHandler(q, auditLog, presigner, recordingURLTTL, authorizer, arSvc),
	}
	if sessionSvc != nil {
		services.Session = session.NewHandler(sessionSvc)
	}
	return services
}

func registerUserServices(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) error {
	rpc.RegisterUserServices(mux, testUserServices(pool, arSvc, sealer, auditLog, sessionSvc, presigner, recordingURLTTL, cookieSecure))
	return nil
}

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

func registerServices(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, setupSvc *dataplane.SetupService, registry *dataplane.Registry, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) error {
	if err := registerUserServices(mux, pool, arSvc, sealer, auditLog, sessionSvc, presigner, recordingURLTTL, cookieSecure); err != nil {
		return err
	}
	return registerMeshServices(mux, pool, auditLog, setupSvc, registry, nil)
}
