package identity_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/auth"
)

// queryPasswordHash reads a user's stored password_hash directly (bypassing the
// API) so tests can assert on the break-glass local-password state.
func queryPasswordHash(t *testing.T, pool *pgxpool.Pool, userID string) string {
	t.Helper()
	var hash string
	if err := pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE id=$1`, userID).Scan(&hash); err != nil {
		t.Fatalf("query password_hash: %v", err)
	}
	return hash
}

// TestCreateUserOptionalPassword proves CreateUser's password is optional: an
// empty password leaves the user local-password-less (SSO-only) — the stored hash
// stays "" (the schema default) rather than a bcrypt/argon2 hash, so
// auth.VerifyPassword rejects every password against it and the account cannot
// local-login until a break-glass password is set via SetLocalPassword.
func TestCreateUserOptionalPassword(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	created, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "sso@x", DisplayName: "SSO",
	}), tok))
	if err != nil {
		t.Fatalf("create with empty password: %v", err)
	}

	hash := queryPasswordHash(t, pool, created.Msg.User.Id)
	if hash != "" {
		t.Fatalf("password_hash = %q, want empty for a password-less (SSO) user", hash)
	}
	if ok, _ := auth.VerifyPassword("anything", hash); ok {
		t.Fatal("VerifyPassword succeeded against a password-less user")
	}
}

// TestSetLocalPassword proves the break-glass local-password path: a holder of
// identity:user:set-password can set a working password on any user (verified via
// auth.VerifyPassword) and clear it back to no local password (VerifyPassword then
// rejects every password).
func TestSetLocalPassword(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	target, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "target@x", DisplayName: "Target",
	}), tok))
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	uid := target.Msg.User.Id

	if _, err := c.SetLocalPassword(ctx, withToken(connect.NewRequest(&identityv1.SetLocalPasswordRequest{
		UserId: uid, NewPassword: "breakglass123",
	}), tok)); err != nil {
		t.Fatalf("set password: %v", err)
	}
	hash := queryPasswordHash(t, pool, uid)
	if ok, err := auth.VerifyPassword("breakglass123", hash); err != nil || !ok {
		t.Fatalf("VerifyPassword after set: ok=%v err=%v", ok, err)
	}

	// The proto only caps new_password's length (max_len); the floor is
	// enforced app-side via auth.ValidatePassword. Pin that SetLocalPassword
	// actually calls it, so a regression that skipped validation on the set
	// path doesn't go uncaught.
	if _, err := c.SetLocalPassword(ctx, withToken(connect.NewRequest(&identityv1.SetLocalPasswordRequest{
		UserId: uid, NewPassword: "short",
	}), tok)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("short password: got %v, want InvalidArgument", err)
	}

	if _, err := c.SetLocalPassword(ctx, withToken(connect.NewRequest(&identityv1.SetLocalPasswordRequest{
		UserId: uid, NewPassword: "",
	}), tok)); err != nil {
		t.Fatalf("clear password: %v", err)
	}
	hash = queryPasswordHash(t, pool, uid)
	if hash != "" {
		t.Fatalf("password_hash after clear = %q, want empty", hash)
	}
	if ok, _ := auth.VerifyPassword("breakglass123", hash); ok {
		t.Fatal("VerifyPassword succeeded against a cleared password")
	}
}
