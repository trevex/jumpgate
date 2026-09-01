package accessrequest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// GrantFilter narrows an admin grant listing. Subject uuid.Nil = any subject.
type GrantFilter struct {
	Subject    uuid.UUID
	ActiveOnly bool
}

// RevokeGrant revokes a single access_grant. The caller may revoke if they hold
// the management revoke capability (mgmtAuthorized, decided by the RPC layer via a
// capability check — admins hold ** so this is a no-op for them), the grant's
// subject (self-revoke), or a STANDING approver for the grant's (role, asset) —
// symmetric with approval authority. On success the revocation is audited and the
// terminator is notified so live sessions relying on the grant are torn down (both
// post-commit, best-effort).
func (s *Service) RevokeGrant(ctx context.Context, caller auth.CurrentUser, mgmtAuthorized bool, grantID uuid.UUID, reason string) (sqlc.AccessGrant, error) {
	g, err := sqlc.New(s.pool).GetGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AccessGrant{}, ErrGrantNotFound
	}
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("get grant: %w", err)
	}

	authorized := mgmtAuthorized || g.SubjectUserID == caller.ID
	if !authorized {
		ok, err := s.resolver.IsApprover(ctx, caller.ID, g.RoleID, g.ScopeAssetID)
		if err != nil {
			return sqlc.AccessGrant{}, err
		}
		authorized = ok
	}
	if !authorized {
		return sqlc.AccessGrant{}, ErrRevokeForbidden
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	revoked, err := q.RevokeGrant(ctx, sqlc.RevokeGrantParams{
		ID:            grantID,
		RevokedBy:     pgtype.UUID{Bytes: caller.ID, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// 0 rows updated: the grant was already revoked or has no live window.
		return sqlc.AccessGrant{}, ErrGrantInactive
	}
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("revoke grant: %w", err)
	}

	if err := s.enqueueRevoked(ctx, q, caller.ID, revoked); err != nil {
		return sqlc.AccessGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("commit: %w", err)
	}

	s.terminate(ctx, revoked.ID)
	return revoked, nil
}

// RevokeGrantsForUser revokes ALL of a user's active grants (used by the
// deactivation cascade). Each revoked grant is audited and its sessions
// terminated. Returns the number of grants revoked.
func (s *Service) RevokeGrantsForUser(ctx context.Context, actor, userID uuid.UUID, reason string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	revoked, err := q.RevokeActiveGrantsForUser(ctx, sqlc.RevokeActiveGrantsForUserParams{
		SubjectUserID: userID,
		RevokedBy:     pgtype.UUID{Bytes: actor, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if err != nil {
		return 0, fmt.Errorf("revoke grants for user: %w", err)
	}
	for _, g := range revoked {
		if err := s.enqueueRevoked(ctx, q, actor, g); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	for _, g := range revoked {
		s.terminate(ctx, g.ID)
	}
	return len(revoked), nil
}

// DeleteRoleCascade deletes a role and everything referencing it, in one
// transaction, so "the role is gone" implies no one holds it and any live sessions
// it granted are torn down. By table:
//
//   - role_bindings, role_grants (either direction): DELETED.
//   - request_policies FOR the role (+ their subjects): DELETED.
//   - request_policies referencing it only as requester_role_id/approver_role_id:
//     SURVIVE with that column NULLed. Those FKs are ON DELETE RESTRICT, so the
//     NULL-out MUST precede the role delete or Postgres rejects it.
//   - live access_grants: REVOKED via the revoke query (audited + terminator
//     notified) before the roles FK cascade removes the rows; the standing-authz
//     sweep is the level-triggered backstop.
//   - roles: DELETED last (frees the name via the partial UNIQUE indexes).
//
// Audit events are enqueued INSIDE the tx (atomic with the deletion); terminator
// notification is POST-COMMIT (must not fire for a change that then rolls back).
func (s *Service) DeleteRoleCascade(ctx context.Context, actor, roleID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	// Revoke the role's still-live grants first (before the FK cascade removes the
	// rows), auditing each so the terminator can tear down their live sessions.
	revoked, err := q.RevokeActiveGrantsForRole(ctx, sqlc.RevokeActiveGrantsForRoleParams{
		RoleID:        roleID,
		RevokedBy:     pgtype.UUID{Bytes: actor, Valid: true},
		RevokedReason: pgtype.Text{String: "role_deleted", Valid: true},
	})
	if err != nil {
		return fmt.Errorf("revoke grants for role: %w", err)
	}
	for _, g := range revoked {
		if err := s.enqueueRevoked(ctx, q, actor, g); err != nil {
			return err
		}
	}

	// Standing references: bindings and rewrite edges (both directions).
	if err := q.DeleteRoleBindingsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role bindings: %w", err)
	}
	if err := q.DeleteRoleGrantsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role grants: %w", err)
	}

	// Request policies: delete those FOR the role (and their subjects); clear the
	// requester/approver gate on policies that only reference it (RESTRICT FKs, so
	// this must happen before the role delete).
	if err := q.DeletePolicySubjectsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete policy subjects: %w", err)
	}
	if err := q.DeletePoliciesForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}
	if err := q.NullRequesterRoleForRole(ctx, pgtype.UUID{Bytes: roleID, Valid: true}); err != nil {
		return fmt.Errorf("null requester role: %w", err)
	}
	if err := q.NullApproverRoleForRole(ctx, pgtype.UUID{Bytes: roleID, Valid: true}); err != nil {
		return fmt.Errorf("null approver role: %w", err)
	}

	// Finally the role itself (frees the name; FK-cascades the revoked grant rows
	// and any access_requests).
	if err := q.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	// Post-commit teardown of the sessions the revoked grants authorized.
	for _, g := range revoked {
		s.terminate(ctx, g.ID)
	}
	return nil
}

// ListMyGrants returns the caller's own grants (active + past), newest first.
func (s *Service) ListMyGrants(ctx context.Context, subject uuid.UUID) ([]Grant, error) {
	rows, err := sqlc.New(s.pool).ListGrantsBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list my grants: %w", err)
	}
	return toGrants(rows), nil
}

// ListMyGrantsPaged returns the caller's own grants with keyset pagination on
// (granted_at DESC, id ASC).
func (s *Service) ListMyGrantsPaged(ctx context.Context, subject uuid.UUID, page PageParams) ([]Grant, error) {
	params := sqlc.ListGrantsBySubjectPagedParams{
		SubjectUserID: subject,
		Lim:           page.Limit,
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsBySubjectPaged(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list my grants paged: %w", err)
	}
	return toGrants(rows), nil
}

// ListGrantsPaged returns grants for admin introspection with keyset pagination
// on (granted_at DESC, id ASC). Filters (subject, active_only) are preserved.
func (s *Service) ListGrantsPaged(ctx context.Context, filter GrantFilter, page PageParams) ([]Grant, error) {
	params := sqlc.ListGrantsFilteredPagedParams{
		ActiveOnly: filter.ActiveOnly,
		Lim:        page.Limit,
	}
	if filter.Subject != uuid.Nil {
		params.SubjectUserID = pgtype.UUID{Bytes: filter.Subject, Valid: true}
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsFilteredPaged(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list grants paged: %w", err)
	}
	return toGrants(rows), nil
}

// ListGrants returns grants for admin introspection (active + past), optionally
// filtered by subject and/or active-only.
func (s *Service) ListGrants(ctx context.Context, filter GrantFilter) ([]Grant, error) {
	params := sqlc.ListGrantsFilteredParams{ActiveOnly: filter.ActiveOnly}
	if filter.Subject != uuid.Nil {
		params.SubjectUserID = pgtype.UUID{Bytes: filter.Subject, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsFiltered(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return toGrants(rows), nil
}

// terminate notifies the terminator that grantID's sessions must be torn down.
// Best-effort: a terminator error is logged, not returned (mirrors audit append).
func (s *Service) terminate(ctx context.Context, grantID uuid.UUID) {
	if s.terminator == nil {
		return
	}
	if err := s.terminator.TerminateGrant(ctx, grantID); err != nil {
		slog.Error("grant terminator failed", "grant_id", grantID.String(), "err", err)
	}
}

// enqueueRevoked writes the grant-revocation audit event into the outbox on the
// caller's tx-bound querier (atomic with the domain write).
func (s *Service) enqueueRevoked(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, g sqlc.AccessGrant) error {
	if s.audit == nil {
		return nil
	}
	reason := ""
	if g.RevokedReason.Valid {
		reason = g.RevokedReason.String
	}
	details := map[string]any{
		"grant_id":   g.ID.String(),
		"request_id": g.RequestID.String(),
		"role_id":    g.RoleID.String(),
		"asset_id":   g.ScopeAssetID.String(),
		"subject":    g.SubjectUserID.String(),
		"reason":     reason,
	}
	raw, _ := json.Marshal(details)
	return s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventGrantRevoked,
		ActorID: actor,
		Subject: "access_grant:" + g.ID.String(),
		Details: raw,
	})
}
