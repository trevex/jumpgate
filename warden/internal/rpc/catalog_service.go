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

// optUUID parses a possibly-empty UUID string. Empty → (pgtype.UUID{}, false, nil).
func optUUID(s string) (pgtype.UUID, bool, error) {
	if s == "" {
		return pgtype.UUID{}, false, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, false, err
	}
	return pgUUID(id), true, nil
}

// CreateRoleBinding grants a role to a subject at a scope (admin only).
func (s *CatalogServer) CreateRoleBinding(ctx context.Context, req *connect.Request[catalogv1.CreateRoleBindingRequest]) (*connect.Response[catalogv1.CreateRoleBindingResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
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
	if hasFolder == hasAsset { // both set or both unset
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("exactly one of scope_folder_id, scope_asset_id is required"))
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
	rb, err := s.q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: roleID, Kind: req.Msg.Kind,
		ScopeFolderID: scopeFolder, ScopeAssetID: scopeAsset,
		SubjectUserID: subjUser, SubjectGroupID: subjGroup,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.CreateRoleBindingResponse{Id: rb.ID.String()}), nil
}

// DeleteRoleBinding removes a binding (admin only). Deleting a non-existent id is a no-op.
func (s *CatalogServer) DeleteRoleBinding(ctx context.Context, req *connect.Request[catalogv1.DeleteRoleBindingRequest]) (*connect.Response[catalogv1.DeleteRoleBindingResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad id"))
	}
	if err := s.q.DeleteRoleBinding(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.DeleteRoleBindingResponse{}), nil
}

// ListVisibleAssets returns the caller's visible assets (active or requestable).
func (s *CatalogServer) ListVisibleAssets(ctx context.Context, _ *connect.Request[catalogv1.ListVisibleAssetsRequest]) (*connect.Response[catalogv1.ListVisibleAssetsResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	vis, err := s.authorizer.VisibleAssets(ctx, u.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListVisibleAssetsResponse{}
	if len(vis) == 0 {
		return connect.NewResponse(out), nil
	}
	ids := make([]uuid.UUID, 0, len(vis))
	for _, v := range vis {
		ids = append(ids, v.AssetID)
	}
	assets, err := s.q.ListAssetsByIDs(ctx, ids)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	nameByID := make(map[uuid.UUID]string, len(assets))
	for _, a := range assets {
		nameByID[a.ID] = a.Name
	}
	for _, v := range vis {
		roleIDs := make([]string, 0, len(v.RoleIDs))
		for _, r := range v.RoleIDs {
			roleIDs = append(roleIDs, r.String())
		}
		out.Assets = append(out.Assets, &catalogv1.VisibleAsset{
			Id: v.AssetID.String(), Name: nameByID[v.AssetID], Active: v.Active, RoleIds: roleIDs,
		})
	}
	return connect.NewResponse(out), nil
}

// GetAssetAccess returns the caller's roles on one asset; NotFound if invisible.
func (s *CatalogServer) GetAssetAccess(ctx context.Context, req *connect.Request[catalogv1.GetAssetAccessRequest]) (*connect.Response[catalogv1.GetAssetAccessResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	roles, err := s.authorizer.RolesOnAsset(ctx, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(roles.Active) == 0 && len(roles.Requestable) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	resp := &catalogv1.GetAssetAccessResponse{}
	for _, r := range roles.Active {
		resp.ActiveRoleIds = append(resp.ActiveRoleIds, r.String())
	}
	for _, r := range roles.Requestable {
		resp.RequestableRoleIds = append(resp.RequestableRoleIds, r.String())
	}
	return connect.NewResponse(resp), nil
}
