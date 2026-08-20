package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"

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
	// A pre-mapped Connect error (e.g. an InvalidArgument from login validation)
	// passes through unchanged rather than being masked as Internal.
	if _, ok := err.(*connect.Error); ok {
		return err
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
	pool       *pgxpool.Pool
	authorizer authz.Authorizer
}

// NewCatalogServer constructs the CatalogService implementation. pool is used to
// run CreateAsset + its inline config as one transaction.
func NewCatalogServer(q *gen.Queries, pool *pgxpool.Pool, authorizer authz.Authorizer) *CatalogServer {
	return &CatalogServer{q: q, pool: pool, authorizer: authorizer}
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
	return &catalogv1.Asset{Id: a.ID.String(), FolderId: a.FolderID.String(), Name: a.Name, Kind: a.Kind}
}

// joinPath builds an asset's DNS-style path: the asset name (the leaf) followed by
// its folder's leaf->root path. folderPath is the containing folder's own leaf-first
// path (empty only defensively — a real asset always has a folder).
func joinPath(folderPath, name string) string {
	if folderPath == "" {
		return name
	}
	return name + "." + folderPath
}

// assetMsgWithPath sets msg.Path = "<asset name>.<folder path>" via a post-commit
// FolderPath lookup. Best-effort: on a lookup error the path is left empty rather than
// failing the create, since the asset is already committed.
func (s *CatalogServer) assetMsgWithPath(ctx context.Context, msg *catalogv1.Asset, folderID uuid.UUID, name string) *catalogv1.Asset {
	fp, err := s.q.FolderPath(ctx, folderID)
	if err == nil {
		msg.Path = joinPath(fp, name)
	}
	return msg
}

// toAssetMsgWithConfig builds an Asset carrying its typed SSH config (host/target
// from the config row plus the per-login rows).
func toAssetMsgWithConfig(a gen.Asset, cfg gen.SshAssetConfig, logins []gen.SshAssetLogin) *catalogv1.Asset {
	msg := toAssetMsg(a)
	out := make([]*catalogv1.SSHLogin, 0, len(logins))
	for _, l := range logins {
		out = append(out, &catalogv1.SSHLogin{
			Login:    l.Login,
			Kind:     l.Kind,
			SecretId: pgUUIDToString(l.SecretID),
		})
	}
	msg.Config = &catalogv1.Asset_Ssh{Ssh: &catalogv1.SSHConfig{
		Logins:        out,
		HostPublicKey: cfg.HostPublicKey,
		TargetAddress: cfg.TargetAddress,
	}}
	return msg
}

// validateSSHConfig checks the parts protovalidate can't: an optional
// host_public_key must be a parseable authorized_keys line, and each login's
// secret_id (when set) must be a UUID.
func validateSSHConfig(ssh *catalogv1.SSHConfig) error {
	if ssh.GetHostPublicKey() != "" {
		if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(ssh.GetHostPublicKey())); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad host_public_key"))
		}
	}
	for _, l := range ssh.GetLogins() {
		if _, _, err := optUUID(l.GetSecretId()); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad secret_id"))
		}
	}
	return nil
}

// upsertSSHConfigParams builds the DB params for an asset's SSH connection config
// (host/target). The per-login rows are written separately.
func upsertSSHConfigParams(assetID uuid.UUID, ssh *catalogv1.SSHConfig) gen.UpsertSSHAssetConfigParams {
	return gen.UpsertSSHAssetConfigParams{
		AssetID:       assetID,
		HostPublicKey: ssh.GetHostPublicKey(),
		TargetAddress: ssh.GetTargetAddress(),
	}
}

// replaceSSHLogins replaces the asset's login set: delete all existing rows, then
// upsert one row per configured login. A CHECK / composite-FK violation (a
// password/key login without a valid same-asset secret) surfaces via the caller's
// mapWriteErr as InvalidArgument.
func replaceSSHLogins(ctx context.Context, q *gen.Queries, assetID uuid.UUID, ssh *catalogv1.SSHConfig) error {
	if err := q.DeleteSSHAssetLoginsForAsset(ctx, assetID); err != nil {
		return err
	}
	for _, l := range ssh.GetLogins() {
		secret, _, err := optUUID(l.GetSecretId())
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad secret_id"))
		}
		if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
			AssetID:  assetID,
			Login:    l.GetLogin(),
			Kind:     l.GetKind(),
			SecretID: secret,
		}); err != nil {
			return err
		}
	}
	return nil
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

// CreateFolder creates a folder (admin only). The folder row and its catalog_names
// entry are written in one transaction so sibling uniqueness is enforced atomically.
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
	name := strings.ToLower(req.Msg.Name)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	f, err := qtx.CreateFolder(ctx, gen.CreateFolderParams{Name: name, ParentID: parent})
	if err != nil {
		return nil, mapWriteErr(err) // a bad parent_id is InvalidArgument, not Internal
	}
	if err := qtx.InsertFolderName(ctx, gen.InsertFolderNameParams{ParentID: parent, Name: name, FolderID: pgUUID(f.ID)}); err != nil {
		return nil, mapWriteErr(err) // sibling collision -> AlreadyExists
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	msg := toFolderMsg(f)
	if path, err := s.q.FolderPath(ctx, f.ID); err == nil {
		msg.Path = path
	}
	return connect.NewResponse(&catalogv1.CreateFolderResponse{Folder: msg}), nil
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
	allPaths, err := s.q.FolderPaths(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	pathByID := make(map[string]string, len(allPaths))
	for _, p := range allPaths {
		pathByID[p.ID.String()] = p.Path
	}
	out := &catalogv1.ListFoldersResponse{}
	for i := range rows {
		m := toFolderMsg(rows[i])
		m.Path = pathByID[rows[i].ID.String()]
		out.Folders = append(out.Folders, m)
	}
	if len(rows) == int(limit) && len(rows) > 0 {
		out.NextPageToken = rows[len(rows)-1].ID.String()
	}
	return connect.NewResponse(out), nil
}

// CreateAsset creates an asset in a folder (admin only). The asset row, its
// catalog_names entry, and any inline SSH config are written in one transaction.
func (s *CatalogServer) CreateAsset(ctx context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	fid, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	kind := req.Msg.Kind
	if kind == "" {
		kind = "ssh"
	}
	name := strings.ToLower(req.Msg.Name)
	params := gen.CreateAssetParams{FolderID: fid, Name: name, Labels: []byte("{}"), Kind: kind}

	ssh := req.Msg.GetSsh()
	if ssh != nil {
		if err := validateSSHConfig(ssh); err != nil {
			return nil, err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	a, err := qtx.CreateAsset(ctx, params)
	if err != nil {
		return nil, mapWriteErr(err) // a bad folder_id is InvalidArgument, not Internal
	}
	if err := qtx.InsertAssetName(ctx, gen.InsertAssetNameParams{ParentID: pgUUID(a.FolderID), Name: name, AssetID: pgUUID(a.ID)}); err != nil {
		return nil, mapWriteErr(err) // sibling collision (incl. vs a folder) -> AlreadyExists
	}

	// Without inline config we still commit the tx (asset + registry row).
	if ssh == nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: s.assetMsgWithPath(ctx, toAssetMsg(a), a.FolderID, a.Name)}), nil
	}

	cfg, err := qtx.UpsertSSHAssetConfig(ctx, upsertSSHConfigParams(a.ID, ssh))
	if err != nil {
		return nil, mapWriteErr(err)
	}
	if err := replaceSSHLogins(ctx, qtx, a.ID, ssh); err != nil {
		return nil, mapWriteErr(err)
	}
	logins, err := qtx.ListSSHAssetLogins(ctx, a.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.CreateAssetResponse{Asset: s.assetMsgWithPath(ctx, toAssetMsgWithConfig(a, cfg, logins), a.FolderID, a.Name)}), nil
}

// GetAsset returns an asset with its typed config (admin only). NotFound if the
// asset does not exist; an asset with no ssh config returns an Asset without config.
func (s *CatalogServer) GetAsset(ctx context.Context, req *connect.Request[catalogv1.GetAssetRequest]) (*connect.Response[catalogv1.GetAssetResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cfg, err := s.q.GetSSHAssetConfig(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return connect.NewResponse(&catalogv1.GetAssetResponse{Asset: s.assetMsgWithPath(ctx, toAssetMsg(a), a.FolderID, a.Name)}), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	logins, err := s.q.ListSSHAssetLogins(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.GetAssetResponse{Asset: s.assetMsgWithPath(ctx, toAssetMsgWithConfig(a, cfg, logins), a.FolderID, a.Name)}), nil
}

// UpdateAssetConfig upserts an asset's typed config (admin only). The
// stored_key_needs_secret CHECK and the stored_secret_id FK surface as
// InvalidArgument.
func (s *CatalogServer) UpdateAssetConfig(ctx context.Context, req *connect.Request[catalogv1.UpdateAssetConfigRequest]) (*connect.Response[catalogv1.UpdateAssetConfigResponse], error) {
	if err := auth.RequireAdmin(ctx); err != nil {
		return nil, err
	}
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	ssh := req.Msg.GetSsh()
	if ssh == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("config required"))
	}
	if err := validateSSHConfig(ssh); err != nil {
		return nil, err
	}
	// Upsert the connection config and replace the login set atomically.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)
	if _, err := qtx.UpsertSSHAssetConfig(ctx, upsertSSHConfigParams(assetID, ssh)); err != nil {
		return nil, mapWriteErr(err)
	}
	if err := replaceSSHLogins(ctx, qtx, assetID, ssh); err != nil {
		return nil, mapWriteErr(err) // CHECK / composite-FK → InvalidArgument
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.UpdateAssetConfigResponse{}), nil
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
	folderPath, err := s.q.FolderPath(ctx, fid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListAssetsByFolderResponse{}
	for i := range rows {
		m := toAssetMsg(rows[i])
		m.Path = joinPath(folderPath, rows[i].Name)
		out.Assets = append(out.Assets, m)
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
