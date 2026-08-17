package bootstrap_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/bootstrap"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func TestBootstrapSeedsAdminOnEmptyDB(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := gen.New(pool)
	ctx := context.Background()

	if err := bootstrap.EnsureAdmin(ctx, q, "root@x", "hunter2hunter2"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	u, err := q.GetUserByEmail(ctx, "root@x")
	if err != nil || !u.IsAdmin {
		t.Fatalf("admin not seeded: %v %+v", err, u)
	}
	ok, _ := auth.VerifyPassword("hunter2hunter2", u.PasswordHash)
	if !ok {
		t.Fatal("seeded admin password mismatch")
	}

	if err := bootstrap.EnsureAdmin(ctx, q, "other@x", "whatever12345"); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if _, err := q.GetUserByEmail(ctx, "other@x"); err == nil {
		t.Fatal("second admin should NOT be created when users exist")
	}
}

func TestBootstrapNoOpWhenUnset(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := gen.New(pool)
	if err := bootstrap.EnsureAdmin(context.Background(), q, "", ""); err != nil {
		t.Fatalf("noop: %v", err)
	}
	n, _ := q.CountUsers(context.Background())
	if n != 0 {
		t.Fatalf("expected 0 users, got %d", n)
	}
}
