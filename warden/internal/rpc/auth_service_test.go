package rpc_test

import (
	"context"
	"crypto/ed25519"
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
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func newServer(t *testing.T) (*pgxpool.Pool, string) {
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

	sealer := testSealer(t)
	sessionSvc, _ := testSessionService(t, pool, sealer)
	mux := http.NewServeMux()
	if err := rpc.Register(mux, pool, testAccessRequestService(pool), sealer, audit.New(pool), sessionSvc, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL
}

// newServerWithSession is newServer that also returns the Ed25519 public key of the
// active session signing key, for tests that verify minted admission tokens.
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

	sealer := testSealer(t)
	sessionSvc, pub := testSessionService(t, pool, sealer)
	mux := http.NewServeMux()
	if err := rpc.Register(mux, pool, testAccessRequestService(pool), sealer, audit.New(pool), sessionSvc, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL, pub
}

// newServerNoVault is newServer with the vault disabled (nil sealer), to exercise
// the fail-closed paths when VAULT_MASTER_KEY is unset.
func newServerNoVault(t *testing.T) (*pgxpool.Pool, string) {
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
	mux := http.NewServeMux()
	if err := rpc.Register(mux, pool, testAccessRequestService(pool), nil, audit.New(pool), nil, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL
}

func seedUser(t *testing.T, pool *pgxpool.Pool, email, pw string, admin bool) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	// Mirror bootstrap.EnsureAdmin: an admin also holds `**` globally via a scopeless
	// standing binding so the capability-gated management handlers admit it.
	if admin {
		role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "admin-" + uuid.NewString(), Capabilities: []byte(`["**"]`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID:        role.ID,
			SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoginAndWhoAmI(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)

	client := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	_, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "nope"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad login code = %v, want Unauthenticated", connect.CodeOf(err))
	}

	resp, err := client.Login(ctx, connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "supersecret"}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.Msg.Token == "" {
		t.Fatalf("unexpected login response: %+v", resp.Msg)
	}

	who := connect.NewRequest(&authv1.WhoAmIRequest{})
	who.Header().Set("Authorization", "Bearer "+resp.Msg.Token)
	wr, err := client.WhoAmI(ctx, who)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if wr.Msg.Email != "admin@x" {
		t.Fatalf("whoami mismatch: %+v", wr.Msg)
	}

	_, err = client.WhoAmI(ctx, connect.NewRequest(&authv1.WhoAmIRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon whoami code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
