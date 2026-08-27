package vault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/internal/access"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/identity"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/recording"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// testMasterKeyB64 is a base64-encoded 32-byte KEK used to build a real sealer so the
// inline-secret sealing write paths are exercised.
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

// fakePresigner is a stand-in Presigner for the recording service (never exercised by
// the vault tests; present only so the full user-service set registers).
type fakePresigner struct{}

func (fakePresigner) PresignGet(_ context.Context, objectKey string, ttl time.Duration) (string, time.Time, error) {
	return "https://recordings.test/get?key=" + objectKey, time.Now().Add(ttl), nil
}

// testAccessRequestService builds a shared access-request Service for the test server.
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

// mountUserServices assembles and registers the full user-facing service set (with the
// vault Handler under test) on mux, using the given sealer. A nil sealer disables the
// vault (fail-closed seal paths).
func mountUserServices(t *testing.T, pool *pgxpool.Pool, sealer *secrets.Sealer) string {
	t.Helper()
	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	authorizer := authz.New(pool)
	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)
	auditLog := audit.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	arSvc := testAccessRequestService(pool)

	services := rpc.UserServices{
		Lookup:        auth.Lookup{Tokens: tokens, Q: q},
		Auth:          auth.NewHandler(q, tokens, authorizer, true),
		Identity:      identity.NewHandler(identity.NewService(pool, arSvc, terminator, authorizer), apiguard.New(authorizer, q)),
		Catalog:       catalog.NewHandler(catalog.NewService(pool, sealer, terminator, authorizer, arSvc), apiguard.New(authorizer, q)),
		Access:        access.NewHandler(access.NewService(pool, roles, authorizer, arSvc, arSvc), apiguard.New(authorizer, q)),
		AccessRequest: accessrequest.NewHandler(resolver, arSvc, authorizer, q),
		Vault:         vault.NewHandler(q, sealer, authorizer),
		Recording:     recording.NewHandler(q, auditLog, fakePresigner{}, time.Minute, authorizer, arSvc),
	}
	mux := http.NewServeMux()
	rpc.RegisterUserServices(mux, services)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// newServer spins up an ephemeral Postgres, migrates it, and mounts the full
// user-facing service set (with the vault Handler under test) on an httptest server.
// It returns the pool and the server URL.
func newServer(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	pool := newPool(t)
	return pool, mountUserServices(t, pool, testSealer(t))
}

// newServerNoVault is newServer with the vault disabled (nil sealer), to exercise the
// fail-closed seal paths when VAULT_MASTER_KEY is unset.
func newServerNoVault(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	pool := newPool(t)
	return pool, mountUserServices(t, pool, nil)
}

// newPool starts an ephemeral Postgres, migrates it, and returns a connected pool.
func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// createRoleWithCaps creates a role and populates its capabilities from a JSON
// capability array string (e.g. `["ssh:login:deploy","**"]`).
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

// seedUser creates a local user with a password; admin=true also binds it to a global
// `**` role so the capability-gated management handlers admit it (mirrors
// bootstrap.EnsureAdmin).
func seedUser(t *testing.T, pool *pgxpool.Pool, email, pw string, admin bool) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)
	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	if admin {
		role := createRoleWithCaps(t, ctx, q, "admin-"+uuid.NewString(), pgtype.UUID{}, `["**"]`)
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        role.ID,
			SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// userIDByEmail looks up a seeded user's id by email.
func userIDByEmail(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatalf("lookup user %s: %v", email, err)
	}
	return id
}

// adminToken logs in the seeded admin (admin@x/supersecret) and returns its bearer token.
func adminToken(t *testing.T, url string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	resp, err := c.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "supersecret"}))
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	return resp.Msg.Token
}

// authClient logs in email/pw and returns the bearer token.
func authClient(t *testing.T, url, email, pw string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	resp, err := c.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: email, Password: pw}))
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return resp.Msg.Token
}

// withToken attaches a bearer token to a Connect request.
func withToken[T any](req *connect.Request[T], tok string) *connect.Request[T] {
	req.Header().Set("Authorization", "Bearer "+tok)
	return req
}
