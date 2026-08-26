package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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

// seedCapUser creates a non-admin local user bound GLOBALLY to a fresh role
// carrying the given capabilities, and returns the user id. It mirrors the admin
// path in seedUser but with a scoped capability set instead of `**`.
func seedCapUser(t *testing.T, pool *pgxpool.Pool, email, pw string, capsJSON string) uuid.UUID {
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
	role := createRoleWithCaps(t, ctx, q, "role-"+uuid.NewString(), pgtype.UUID{}, capsJSON)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return u.ID
}
