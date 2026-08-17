package rpc

import (
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// CatalogServer implements catalogv1connect.CatalogServiceHandler.
type CatalogServer struct {
	q          *gen.Queries
	authorizer authz.Authorizer
}

// NewCatalogServer constructs the CatalogService implementation.
func NewCatalogServer(q *gen.Queries, authorizer authz.Authorizer) *CatalogServer {
	return &CatalogServer{q: q, authorizer: authorizer}
}

func pgUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func toFolderMsg(f gen.Folder) *catalogv1.Folder {
	return &catalogv1.Folder{Id: f.ID.String(), Name: f.Name, ParentId: pgUUIDToString(f.ParentID)}
}

func toAssetMsg(a gen.Asset) *catalogv1.Asset {
	return &catalogv1.Asset{Id: a.ID.String(), FolderId: a.FolderID.String(), Name: a.Name}
}

func toRoleMsg(r gen.Role) *catalogv1.Role {
	var caps []string
	_ = json.Unmarshal(r.Capabilities, &caps)
	return &catalogv1.Role{Id: r.ID.String(), Name: r.Name, ResourceType: r.ResourceType, Capabilities: caps}
}

// CreateFolder creates a folder (admin only).
func (s *CatalogServer) CreateFolder(ctx context.Context, req *connect.Request[catalogv1.CreateFolderRequest]) (*connect.Response[catalogv1.CreateFolderResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	var parent pgtype.UUID
	if req.Msg.ParentId != "" {
		pid, err := uuid.Parse(req.Msg.ParentId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad parent_id"))
		}
		parent = pgUUID(pid)
	}
	f, err := s.q.CreateFolder(ctx, gen.CreateFolderParams{Name: req.Msg.Name, ParentID: parent})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.CreateFolderResponse{Folder: toFolderMsg(f)}), nil
}

// ListFolders lists folders (admin only).
func (s *CatalogServer) ListFolders(ctx context.Context, req *connect.Request[catalogv1.ListFoldersRequest]) (*connect.Response[catalogv1.ListFoldersResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	limit := req.Msg.PageSize
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	after := uuid.Nil
	if req.Msg.PageToken != "" {
		id, err := uuid.Parse(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
		}
		after = id
	}
	rows, err := s.q.ListFolders(ctx, gen.ListFoldersParams{Column1: after, Limit: limit})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListFoldersResponse{}
	for i := range rows {
		out.Folders = append(out.Folders, toFolderMsg(rows[i]))
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// CreateAsset creates an asset in a folder (admin only).
func (s *CatalogServer) CreateAsset(ctx context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	fid, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	a, err := s.q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: fid, Name: req.Msg.Name, Labels: []byte("{}")})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: toAssetMsg(a)}), nil
}

// ListAssetsByFolder lists a folder's assets (admin only).
// ListAssetsByFolder's generated signature takes uuid.UUID (folder_id is NOT NULL),
// so fid is passed directly without pgUUID wrapping.
func (s *CatalogServer) ListAssetsByFolder(ctx context.Context, req *connect.Request[catalogv1.ListAssetsByFolderRequest]) (*connect.Response[catalogv1.ListAssetsByFolderResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	fid, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	rows, err := s.q.ListAssetsByFolder(ctx, fid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListAssetsByFolderResponse{}
	for i := range rows {
		out.Assets = append(out.Assets, toAssetMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// CreateRole creates a custom role (admin only).
func (s *CatalogServer) CreateRole(ctx context.Context, req *connect.Request[catalogv1.CreateRoleRequest]) (*connect.Response[catalogv1.CreateRoleResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	capsJSON, err := json.Marshal(req.Msg.Capabilities)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	r, err := s.q.CreateRole(ctx, gen.CreateRoleParams{Name: req.Msg.Name, ResourceType: req.Msg.ResourceType, Capabilities: capsJSON})
	if err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("role already exists"))
	}
	return connect.NewResponse(&catalogv1.CreateRoleResponse{Role: toRoleMsg(r)}), nil
}

// ListRoles lists roles (admin only).
func (s *CatalogServer) ListRoles(ctx context.Context, req *connect.Request[catalogv1.ListRolesRequest]) (*connect.Response[catalogv1.ListRolesResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	limit := req.Msg.PageSize
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	after := uuid.Nil
	if req.Msg.PageToken != "" {
		id, err := uuid.Parse(req.Msg.PageToken)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad page_token"))
		}
		after = id
	}
	rows, err := s.q.ListRoles(ctx, gen.ListRolesParams{Column1: after, Limit: limit})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListRolesResponse{}
	for i := range rows {
		out.Roles = append(out.Roles, toRoleMsg(rows[i]))
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// CreateRoleBinding — implemented in Task 6.
func (s *CatalogServer) CreateRoleBinding(_ context.Context, _ *connect.Request[catalogv1.CreateRoleBindingRequest]) (*connect.Response[catalogv1.CreateRoleBindingResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// DeleteRoleBinding — implemented in Task 6.
func (s *CatalogServer) DeleteRoleBinding(_ context.Context, _ *connect.Request[catalogv1.DeleteRoleBindingRequest]) (*connect.Response[catalogv1.DeleteRoleBindingResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// ListVisibleAssets — implemented in Task 7.
func (s *CatalogServer) ListVisibleAssets(_ context.Context, _ *connect.Request[catalogv1.ListVisibleAssetsRequest]) (*connect.Response[catalogv1.ListVisibleAssetsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// GetAssetAccess — implemented in Task 7.
func (s *CatalogServer) GetAssetAccess(_ context.Context, _ *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
