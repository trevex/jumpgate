package rpc_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
)

// strptr returns a pointer to s (for optional proto string fields).
func strptr(s string) *string { return &s }

// userID returns the id of a previously seeded user by email.
func userID(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email=$1`, email).Scan(&id); err != nil {
		t.Fatalf("lookup user %q: %v", email, err)
	}
	return id
}

// fakeReqReads is a controllable requestReadAuthorizer for the display-read tests
// (GetAssetDisplay / GetRoleDisplay): it grants or denies the request-party path.
type fakeReqReads struct {
	allow bool
	err   error
}

func (f fakeReqReads) CanReadForRequest(_ context.Context, _ uuid.UUID, _ accessrequest.ReqEntityKind, _ uuid.UUID) (bool, error) {
	return f.allow, f.err
}
