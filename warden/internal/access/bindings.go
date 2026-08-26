package access

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// CreateRoleBinding grants a role to a subject at a scope. The caller's
// access:binding:create capability at bindScope is gated by the handler; the service
// then enforces the no-escalation subset rule (requireGrantable — every capability
// the role grants must be held by the caller at bindScope) and the folder-scoped role
// containment invariant, before writing the binding.
func (s *Service) CreateRoleBinding(ctx context.Context, caller, roleID uuid.UUID, scopeFolder, scopeAsset, subjUser, subjGroup pgtype.UUID, bindScope authz.Scope) (sqlc.RoleBinding, error) {
	caps, err := s.roleCaps(ctx, roleID)
	if err != nil {
		return sqlc.RoleBinding{}, err
	}
	if err := s.requireGrantable(ctx, caller, caps, bindScope); err != nil {
		return sqlc.RoleBinding{}, err
	}
	if err := s.containedInRoleSubtree(ctx, roleID, scopeFolder, scopeAsset); err != nil {
		return sqlc.RoleBinding{}, err
	}
	rb, err := s.q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        roleID,
		ScopeFolderID: scopeFolder, ScopeAssetID: scopeAsset,
		SubjectUserID: subjUser, SubjectGroupID: subjGroup,
	})
	if err != nil {
		return sqlc.RoleBinding{}, apierr.MapWrite(err)
	}
	return rb, nil
}

// DeleteRoleBinding removes a binding by id. The caller's capability
// (access:binding:delete at the binding's scope) is gated by the handler.
func (s *Service) DeleteRoleBinding(ctx context.Context, id uuid.UUID) error {
	if err := s.q.DeleteRoleBinding(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// ListRoleBindings lists bindings matching the (all-optional) filters, ordered by
// (created_at DESC, id) with keyset pagination. The caller's access:binding:read
// capability at the queried scope is gated by the handler. Returns the page rows and
// an opaque next-page token.
func (s *Service) ListRoleBindings(ctx context.Context, roleID, scopeFolder, scopeAsset, subjUser, subjGroup pgtype.UUID, pageSize int32, pageToken string) ([]sqlc.RoleBinding, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListRoleBindingsParams{
		RoleID:         roleID,
		ScopeFolderID:  scopeFolder,
		ScopeAssetID:   scopeAsset,
		SubjectUserID:  subjUser,
		SubjectGroupID: subjGroup,
		Lim:            limit,
	}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListRoleBindings(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the standard
	// strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY column: here
	// created_at.
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}
