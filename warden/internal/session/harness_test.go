package session_test

import (
	"context"
	"crypto/ed25519"
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
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// testSessionTTL / testGatewayEndpoint are the fixed session-admission params used
// by the session test servers.
const (
	testSessionTTL      = 60 * time.Second
	testGatewayEndpoint = "gateway.test:8443"
)

// fakePresigner is a stand-in Presigner for the recording service (never exercised by
// the session tests; present only so the full user-service set registers).
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

// newServerWithSession spins up an ephemeral Postgres, migrates it, and mounts the
// full user-facing service set — including the session Handler under test, wired to
// an initialized session signing key — on an httptest server. It returns the pool,
// the server URL, and the Ed25519 signing public key so tests can verify minted
// session tokens. The session tests drive the session Connect client over this URL.
func newServerWithSession(t *testing.T) (*pgxpool.Pool, string, ed25519.PublicKey) {
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

	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	authorizer := authz.NewSQLAuthorizer(pool)
	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)
	auditLog := audit.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	arSvc := testAccessRequestService(pool)
	sealer := testSealer(t)
	sessionSvc, signPub := testSessionService(t, pool, sealer)

	services := rpc.UserServices{
		Lookup:        auth.Lookup{Tokens: tokens, Q: q},
		Auth:          auth.NewHandler(q, tokens, authorizer, true),
		Identity:      identity.NewHandler(identity.NewService(pool, arSvc, terminator, authorizer), apiguard.New(authorizer, q)),
		Catalog:       catalog.NewHandler(catalog.NewService(pool, sealer, terminator, authorizer, arSvc), apiguard.New(authorizer, q)),
		Access:        access.NewHandler(access.NewService(pool, roles, authorizer, arSvc, arSvc), apiguard.New(authorizer, q)),
		AccessRequest: accessrequest.NewHandler(resolver, arSvc, authorizer, q),
		Vault:         vault.NewHandler(q, sealer, authorizer),
		Recording:     recording.NewHandler(q, auditLog, fakePresigner{}, time.Minute, authorizer, arSvc),
		Session:       session.NewHandler(sessionSvc),
	}
	mux := http.NewServeMux()
	rpc.RegisterUserServices(mux, services)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL, signPub
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

// pgU wraps a uuid.UUID as a valid pgtype.UUID (test helper).
func pgU(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
