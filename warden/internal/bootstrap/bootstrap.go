// Package bootstrap seeds an initial admin user on first startup.
package bootstrap

import (
	"context"
	"fmt"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// EnsureAdmin creates an admin user with the given credentials, but only when the
// users table is empty. No-op if any users exist, or if email/password is empty.
func EnsureAdmin(ctx context.Context, q *gen.Queries, email, password string) error {
	if email == "" || password == "" {
		return nil
	}
	n, err := q.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email, IsAdmin: true})
	if err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	return nil
}
