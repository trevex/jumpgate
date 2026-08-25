// Package bootstrap seeds an initial admin user on first startup.
package bootstrap

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// EnsureAdmin creates an admin user with the given credentials, but only when the
// users table is empty. No-op if any users exist, or if email/password is empty.
func EnsureAdmin(ctx context.Context, q *sqlc.Queries, email, password string) error {
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
	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		return fmt.Errorf("create admin: %w", err)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return fmt.Errorf("set password: %w", err)
	}

	// Grant the admin an `admin` role carrying `**` (match-everything) via a
	// scopeless (global) standing binding. This is the ONLY thing that admits the
	// admin through the capability-gated management handlers (there is no is_admin
	// boolean anymore; management authz is capability-only).
	role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "admin"}) // FolderID zero-value = NULL = global role
	if err != nil {
		return fmt.Errorf("create admin role: %w", err)
	}
	s, a, qv := authz.NormalizeCap("**")
	if err := q.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{RoleID: role.ID, Scope: s, Action: a, Qualifier: qv}); err != nil {
		return fmt.Errorf("insert admin cap: %w", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		// scope_* + subject_group_id left zero-value/NULL => scopeless GLOBAL binding
	}); err != nil {
		return fmt.Errorf("bind admin role: %w", err)
	}
	return nil
}
