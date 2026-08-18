package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/internal/auth"
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

	mux := http.NewServeMux()
	if err := rpc.Register(mux, pool, testAccessRequestService(pool)); err != nil {
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
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email, IsAdmin: admin})
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
	if resp.Msg.Token == "" || !resp.Msg.IsAdmin {
		t.Fatalf("unexpected login response: %+v", resp.Msg)
	}

	who := connect.NewRequest(&authv1.WhoAmIRequest{})
	who.Header().Set("Authorization", "Bearer "+resp.Msg.Token)
	wr, err := client.WhoAmI(ctx, who)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if wr.Msg.Email != "admin@x" || !wr.Msg.IsAdmin {
		t.Fatalf("whoami mismatch: %+v", wr.Msg)
	}

	_, err = client.WhoAmI(ctx, connect.NewRequest(&authv1.WhoAmIRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon whoami code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}
