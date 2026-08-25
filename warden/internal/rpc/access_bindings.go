package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// CreateRoleBinding grants a role to a subject at a scope (admin only).
func (s *AccessServer) CreateRoleBinding(ctx context.Context, req *connect.Request[accessv1.CreateRoleBindingRequest]) (*connect.Response[accessv1.CreateRoleBindingResponse], error) {
	roleID, err := uuid.Parse(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, hasFolder, err := optUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, hasAsset, err := optUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	if hasFolder && hasAsset {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most one of scope_folder_id, scope_asset_id may be set"))
	}
	subjUser, hasUser, err := optUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, hasGroup, err := optUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	if hasUser == hasGroup {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of subject_user_id, subject_group_id is required"))
	}
	bindScope := scopeOfObject(scopeFolder, scopeAsset)
	if err := s.requireCap(ctx, "access:binding:create", bindScope); err != nil {
		return nil, err
	}
	caps, err := s.roleCaps(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGrantable(ctx, caps, bindScope); err != nil {
		return nil, err
	}
	if err := s.containedInRoleSubtree(ctx, roleID, scopeFolder, scopeAsset); err != nil {
		return nil, err
	}
	rb, err := s.q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        roleID,
		ScopeFolderID: scopeFolder, ScopeAssetID: scopeAsset,
		SubjectUserID: subjUser, SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&accessv1.CreateRoleBindingResponse{Id: rb.ID.String()}), nil
}

// DeleteRoleBinding removes a binding (admin only). Loads the binding to derive
// its scope, so a missing id returns NotFound.
func (s *AccessServer) DeleteRoleBinding(ctx context.Context, req *connect.Request[accessv1.DeleteRoleBindingRequest]) (*connect.Response[accessv1.DeleteRoleBindingResponse], error) {
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	scope, err := s.scopeOfBinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "access:binding:delete", scope); err != nil {
		return nil, err
	}
	if err := s.q.DeleteRoleBinding(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&accessv1.DeleteRoleBindingResponse{}), nil
}

// ListRoleBindings lists bindings matching the (all-optional) filters. It is
// authorized by access:binding:read at the QUERIED scope: when the caller pins a
// scope_asset_id / scope_folder_id (as the catalog detail panes do), the cap is
// checked at that object scope — so a folder-delegated admin can read the bindings
// in their subtree — while an unscoped "list all" query still requires the cap
// globally. Results are ordered by (created_at DESC, id) with keyset pagination.
func (s *AccessServer) ListRoleBindings(ctx context.Context, req *connect.Request[accessv1.ListRoleBindingsRequest]) (*connect.Response[accessv1.ListRoleBindingsResponse], error) {
	roleID, _, err := optUUID(req.Msg.RoleId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	scopeFolder, _, err := optUUID(req.Msg.ScopeFolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_folder_id"))
	}
	scopeAsset, _, err := optUUID(req.Msg.ScopeAssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
	}
	// Scope the cap check to the pinned object (asset > folder > global).
	if err := s.requireCap(ctx, "access:binding:read", scopeOfObject(scopeFolder, scopeAsset)); err != nil {
		return nil, err
	}
	subjUser, _, err := optUUID(req.Msg.SubjectUserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_user_id"))
	}
	subjGroup, _, err := optUUID(req.Msg.SubjectGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad subject_group_id"))
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
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
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &accessv1.ListRoleBindingsResponse{}
	for i := range rows {
		out.Bindings = append(out.Bindings, toRoleBindingMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// therefore costs one extra round-trip returning an empty final page (the
	// standard strict-last-page tradeoff). encodeTimeToken takes the SORT-KEY
	// column: here created_at — for tables ordered by a different column (e.g.
	// access_grants.granted_at) use that column instead.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}
