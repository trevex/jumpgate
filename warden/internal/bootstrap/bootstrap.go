// Package bootstrap seeds an initial admin user on first startup.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

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

	// Also grant the admin an `admin` role carrying `**` (match-everything) via a
	// scopeless (global) standing binding. This admits the admin through the
	// capability-gated management handlers. IsAdmin above remains set during the
	// transitional period while handlers accept both gate styles.
	caps, err := json.Marshal([]string{"**"})
	if err != nil {
		return fmt.Errorf("marshal admin caps: %w", err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "admin", Capabilities: caps}) // FolderID zero-value = NULL = global role
	if err != nil {
		return fmt.Errorf("create admin role: %w", err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        role.ID,
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		// scope_* + subject_group_id left zero-value/NULL => scopeless GLOBAL binding
	}); err != nil {
		return fmt.Errorf("bind admin role: %w", err)
	}
	return nil
}
