package access

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AddRoleGrant adds a role-rewrite rule "holding sourceRoleID CONFERS roleID". The
// caller's access:role:update capability at the RECIPIENT role's scope is gated by
// the handler; the service then enforces the no-escalation subset rule against the
// RECIPIENT role's capabilities (holding source confers roleID, so the caller must be
// able to grant roleID's capabilities), rejects a same-object self-reference, and
// writes the edge. Mirrors the DB constraints: a duplicate rule is AlreadyExists; an
// unknown role is InvalidArgument.
func (s *Service) AddRoleGrant(ctx context.Context, caller, roleID, sourceRoleID uuid.UUID, via string, scope authz.Scope) (sqlc.RoleGrant, error) {
	caps, err := s.guard.RoleCaps(ctx, roleID)
	if err != nil {
		return sqlc.RoleGrant{}, err
	}
	if err := s.guard.RequireGrantable(ctx, caller, caps, scope); err != nil {
		return sqlc.RoleGrant{}, err
	}
	if via == "same_object" && roleID == sourceRoleID {
		return sqlc.RoleGrant{}, connect.NewError(connect.CodeInvalidArgument, errors.New("same-object self-reference not allowed"))
	}
	g, err := s.q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: roleID, SourceRoleID: sourceRoleID, Via: via})
	if err != nil {
		return sqlc.RoleGrant{}, apierr.MapWrite(err)
	}
	return g, nil
}

// RemoveRoleGrant deletes a role-rewrite rule by id. The caller's capability
// (access:role:update at the grant's recipient-role scope, or global for a no-op on a
// missing grant) is gated by the handler. Removing a grant only REMOVES conferred
// authority (de-escalation), so no grantable subset check is required.
func (s *Service) RemoveRoleGrant(ctx context.Context, id uuid.UUID) error {
	if err := s.q.DeleteRoleGrant(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// ListRoleGrants lists the rewrite rules conferring roleID, ordered by (created_at
// DESC, id ASC). The caller's access:role:read capability at the role's scope is gated
// by the handler. Returns the page rows and an opaque next-page token.
func (s *Service) ListRoleGrants(ctx context.Context, roleID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.RoleGrant, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListRoleGrantsParams{RoleID: roleID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRoleGrants(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}
