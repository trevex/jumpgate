package identity_test

import (
	"context"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/identity"
)

// TestCreateUserAtomicOnPasswordFailure pins that CreateUser is transactional: the
// user row and the password write commit together, so if the password write fails
// NO user row is left behind. It forces the second write (SetUserPassword) to fail
// by adding a CHECK constraint that a real bcrypt hash (60 chars) violates while the
// NULL password_hash of the freshly-inserted user row (CreateUserFull) satisfies it.
// Before the fix (two writes outside a tx) the user row would survive the failed
// password write.
func TestCreateUserAtomicOnPasswordFailure(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// Any non-null password_hash must be < 5 chars → a 60-char bcrypt hash write fails,
	// but CreateUserFull (which leaves password_hash NULL) still succeeds.
	if _, err := pool.Exec(ctx, `ALTER TABLE users ADD CONSTRAINT pw_short CHECK (password_hash IS NULL OR length(password_hash) < 5)`); err != nil {
		t.Fatalf("add check constraint: %v", err)
	}

	svc := identity.NewService(pool, nil, nil, authz.NewSQLAuthorizer(pool))
	if _, err := svc.CreateUser(ctx, "atomic@x", "Atomic", "password123"); err == nil {
		t.Fatal("CreateUser succeeded, want error from the failing password write")
	}

	// The transaction must have rolled back: no user row remains.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email='atomic@x'`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Fatalf("user rows after failed password write = %d, want 0 (CreateUser not atomic)", n)
	}
}
