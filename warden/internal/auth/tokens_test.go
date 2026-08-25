package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

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

func TestTokenIssueValidateRevoke(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	svc := auth.NewTokenService(q)

	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "t@x", DisplayName: "T"})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := svc.Issue(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	got, err := svc.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got != u.ID {
		t.Fatalf("validate userID = %v, want %v", got, u.ID)
	}

	if err := svc.Revoke(ctx, tok); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Validate(ctx, tok); err == nil {
		t.Fatal("revoked token still validates")
	}

	if _, err := svc.Validate(ctx, "not-a-real-token"); err == nil {
		t.Fatal("bogus token validated")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	svc := auth.NewTokenService(q)
	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "e@x", DisplayName: "E"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Issue(ctx, u.ID, -1*time.Minute) // already expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, tok); err == nil {
		t.Fatal("expired token validated")
	}
}
