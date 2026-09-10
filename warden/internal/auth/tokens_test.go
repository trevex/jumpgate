package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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

	tok, err := svc.Issue(ctx, u.ID, time.Hour, auth.TokenMeta{})
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
	tok, err := svc.Issue(ctx, u.ID, -1*time.Minute, auth.TokenMeta{}) // already expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, tok); err == nil {
		t.Fatal("expired token validated")
	}
}

func TestListAndRevokeByID(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "list@x", DisplayName: "L"})
	if err != nil {
		t.Fatal(err)
	}
	row, err := q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{
		UserID:    u.ID,
		TokenHash: []byte("hash-1"),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		ClientIp:  pgtype.Text{String: "10.0.0.1", Valid: true},
		UserAgent: pgtype.Text{String: "cli", Valid: true},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = q.CreateAuthToken(ctx, sqlc.CreateAuthTokenParams{
		UserID:    u.ID,
		TokenHash: []byte("hash-expired"),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("create expired: %v", err)
	}
	sessions, err := q.ListAuthTokensByUser(ctx, u.ID)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("list: %v len=%d", err, len(sessions))
	}
	if sessions[0].ClientIp.String != "10.0.0.1" {
		t.Fatalf("client_ip = %q", sessions[0].ClientIp.String)
	}

	other, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "other@x", DisplayName: "O"})
	if err != nil {
		t.Fatal(err)
	}
	// Wrong owner: must delete nothing.
	n0, err := q.DeleteAuthTokenByIDForUser(ctx, sqlc.DeleteAuthTokenByIDForUserParams{ID: row.ID, UserID: other.ID})
	if err != nil || n0 != 0 {
		t.Fatalf("cross-user delete should be no-op: err=%v n=%d", err, n0)
	}
	// Correct owner: deletes exactly one.
	n, err := q.DeleteAuthTokenByIDForUser(ctx, sqlc.DeleteAuthTokenByIDForUserParams{ID: row.ID, UserID: u.ID})
	if err != nil || n != 1 {
		t.Fatalf("owner delete: %v n=%d", err, n)
	}
}

func TestIdleTimeoutRejects(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	svc := auth.NewTokenService(q, auth.WithIdleTTL(time.Hour))
	u, _ := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "idle@x", DisplayName: "I"})

	tok, err := svc.Issue(ctx, u.ID, 12*time.Hour, auth.TokenMeta{ClientIP: "1.2.3.4", UserAgent: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE auth_tokens SET last_used_at = now() - interval '2 hours' WHERE user_id = $1", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, tok); err == nil {
		t.Fatal("idle-expired token still validates")
	}
}

func TestRevokeAllForUser(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	svc := auth.NewTokenService(q)
	u, _ := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "all@x", DisplayName: "A"})
	keep, _ := svc.Issue(ctx, u.ID, time.Hour, auth.TokenMeta{})
	_, _ = svc.Issue(ctx, u.ID, time.Hour, auth.TokenMeta{})

	n, err := svc.RevokeAllExcept(ctx, u.ID, keep)
	if err != nil || n != 1 {
		t.Fatalf("revoke-all-except: %v n=%d", err, n)
	}
	if _, err := svc.Validate(ctx, keep); err != nil {
		t.Fatal("kept token was revoked")
	}
}
