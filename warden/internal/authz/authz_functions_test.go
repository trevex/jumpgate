package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustSeedUser creates one active user and returns its id. Shared by the Phase 1
// parity tests. Uses *pgxpool.Pool to match the existing seeders in testhelpers_test.go.
func mustSeedUser(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users(email, display_name) VALUES($1,$1) RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return id
}

func TestActiveAccessGrantsView(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// Fresh DB: no grants yet -> the view exists and returns 0 rows without error.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM active_access_grants`).Scan(&count); err != nil {
		t.Fatalf("query view: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 active grants on fresh db, got %d", count)
	}

	// authz_user_is_active exists and rejects a non-existent user.
	var active bool
	if err := pool.QueryRow(ctx, `SELECT authz_user_is_active($1)`, uuid.New()).Scan(&active); err != nil {
		t.Fatalf("scalar: %v", err)
	}
	if active {
		t.Fatalf("random uuid must not be an active user")
	}

	// A freshly seeded (non-deactivated) user IS active.
	u := mustSeedUser(t, pool, "active-scalar@x")
	if err := pool.QueryRow(ctx, `SELECT authz_user_is_active($1)`, u).Scan(&active); err != nil {
		t.Fatalf("scalar seeded: %v", err)
	}
	if !active {
		t.Fatalf("freshly seeded user must be active")
	}
	_ = pgx.ErrNoRows // keep the pgx import used across the file's Phase 1 tests
}
