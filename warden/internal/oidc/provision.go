package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// oidcOrigin marks a group_memberships row as IdP-managed, distinguishing it
// from a manually-granted membership so SyncGroups only ever adds/removes
// rows it owns.
const oidcOrigin = "oidc"

// Provisioner owns the two write paths triggered by a successful OIDC login:
// resolving/JIT-creating the local user for an (issuer, subject), and
// reconciling that user's IdP-group memberships.
type Provisioner struct {
	pool *pgxpool.Pool
}

// NewProvisioner builds a Provisioner over pool.
func NewProvisioner(pool *pgxpool.Pool) *Provisioner {
	return &Provisioner{pool: pool}
}

// ResolveOrProvision returns the jumpgate user id bound to (issuer, subject),
// creating a new local user + identity on first login (JIT provisioning).
//
// Security-relevant behavior:
//   - An existing identity whose user is deactivated returns ErrDeactivated,
//     never a usable user id.
//   - JIT creation normalizes the email (auth.NormalizeEmail) and relies on the
//     DB's case-insensitive unique index; a collision with an existing local
//     account returns ErrEmailCollision rather than silently taking over (or
//     merging into) that account.
func (p *Provisioner) ResolveOrProvision(ctx context.Context, issuer, subject string, c Claims) (uuid.UUID, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("oidc: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	u, err := q.GetUserByIdentity(ctx, sqlc.GetUserByIdentityParams{Issuer: issuer, Subject: subject})
	switch {
	case err == nil:
		if u.DeactivatedAt.Valid {
			return uuid.Nil, ErrDeactivated
		}
		// No write occurred; rollback (the deferred call) is sufficient, but
		// commit is harmless and keeps the tx lifecycle uniform.
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, fmt.Errorf("oidc: commit: %w", err)
		}
		return u.ID, nil

	case errors.Is(err, pgx.ErrNoRows):
		nu, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{
			Email:       auth.NormalizeEmail(c.Email),
			DisplayName: displayName(c),
		})
		if err != nil {
			if apierr.IsUniqueViolation(err) {
				return uuid.Nil, ErrEmailCollision
			}
			return uuid.Nil, fmt.Errorf("oidc: create user: %w", err)
		}
		if err := q.CreateUserIdentity(ctx, sqlc.CreateUserIdentityParams{
			UserID:  nu.ID,
			Issuer:  issuer,
			Subject: subject,
		}); err != nil {
			if apierr.IsUniqueViolation(err) {
				// Lost a race with another concurrent first-login for the same
				// (issuer, subject); the other request's identity wins.
				return uuid.Nil, ErrEmailCollision
			}
			return uuid.Nil, fmt.Errorf("oidc: create identity: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, fmt.Errorf("oidc: commit: %w", err)
		}
		return nu.ID, nil

	default:
		return uuid.Nil, fmt.Errorf("oidc: lookup identity: %w", err)
	}
}

// displayName prefers the IdP's asserted name, falling back to the email so a
// JIT-provisioned user never has a blank display name.
func displayName(c Claims) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Email
}

// SyncGroups reconciles userID's OIDC-origin group memberships to exactly
// match claimGroups (IdP group claim values), mapped through
// groups.external_key. Unmatched claim values (no group has that
// external_key) are ignored. A group where the user already holds a
// manually-granted ('manual' origin) membership is never touched — adds are
// ON CONFLICT DO NOTHING and deletes are scoped to origin='oidc' rows only.
//
// Deletes fire the existing authz-change trigger (session teardown on lost
// access); adds deliberately don't — that mirrors how a fresh grant behaves
// elsewhere and is intended, not an oversight.
func (p *Provisioner) SyncGroups(ctx context.Context, userID uuid.UUID, claimGroups []string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("oidc: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	memberUserID := pgconv.UUID(userID)

	resolved := make(map[uuid.UUID]struct{}, len(claimGroups))
	for _, key := range claimGroups {
		g, err := q.GetGroupByExternalKey(ctx, pgconv.Text(key))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue // unmatched claim value: no group maps to it, ignore
			}
			return fmt.Errorf("oidc: resolve group %q: %w", key, err)
		}
		resolved[g.ID] = struct{}{}
	}

	currentIDs, err := q.ListOIDCGroupIDsForUser(ctx, memberUserID)
	if err != nil {
		return fmt.Errorf("oidc: list current oidc groups: %w", err)
	}
	current := make(map[uuid.UUID]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		current[id] = struct{}{}
	}

	for id := range resolved {
		if _, ok := current[id]; ok {
			continue
		}
		if err := q.AddUserToGroupWithOrigin(ctx, sqlc.AddUserToGroupWithOriginParams{
			GroupID:      id,
			MemberUserID: memberUserID,
			Origin:       oidcOrigin,
		}); err != nil {
			return fmt.Errorf("oidc: add group membership %s: %w", id, err)
		}
	}
	for id := range current {
		if _, ok := resolved[id]; ok {
			continue
		}
		if err := q.DeleteOIDCMembership(ctx, sqlc.DeleteOIDCMembershipParams{
			MemberUserID: memberUserID,
			GroupID:      id,
		}); err != nil {
			return fmt.Errorf("oidc: remove group membership %s: %w", id, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oidc: commit: %w", err)
	}
	return nil
}
