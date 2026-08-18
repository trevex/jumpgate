package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// PostgreSQL SQLSTATE codes used to map DB constraint failures to Connect codes.
const (
	pgerrcodeUniqueViolation     = "23505"
	pgerrcodeForeignKeyViolation = "23503"
	pgerrcodeCheckViolation      = "23514"
)

// mapWriteErr maps a Postgres write error to an appropriate Connect code so that
// bad client input (a reference to a non-existent role/scope/subject, a violated
// constraint) surfaces as InvalidArgument/AlreadyExists rather than Internal.
// Returns nil for a nil error.
func mapWriteErr(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcodeUniqueViolation:
			return connect.NewError(connect.CodeAlreadyExists, errors.New("already exists"))
		case pgerrcodeForeignKeyViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("references a non-existent entity"))
		case pgerrcodeCheckViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("violates a constraint"))
		}
	}
	return connect.NewError(connect.CodeInternal, err)
}

// CatalogServer implements catalogv1connect.CatalogServiceHandler: folders,
// assets, and the caller's visible-asset catalog. Authorization config lives in
// AccessService.
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
		return nil, mapWriteErr(err) // a bad parent_id is InvalidArgument, not Internal
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
		return nil, mapWriteErr(err) // a bad folder_id is InvalidArgument, not Internal
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
