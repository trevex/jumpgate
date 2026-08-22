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
	capGuard
	q          *gen.Queries
	pool       *pgxpool.Pool
	authorizer authz.Authorizer
}

// NewCatalogServer constructs the CatalogService implementation. pool is used to
// run CreateAsset + its inline config as one transaction.
func NewCatalogServer(q *gen.Queries, pool *pgxpool.Pool, authorizer authz.Authorizer) *CatalogServer {
	return &CatalogServer{capGuard: capGuard{authz: authorizer, q: q}, q: q, pool: pool, authorizer: authorizer}
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
	var parent pgtype.UUID
	if req.Msg.ParentId != "" {
		pid, err := uuid.Parse(req.Msg.ParentId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad parent_id"))
		}
		parent = pgUUID(pid)
	}
	if err := s.requireCap(ctx, "catalog:folder:create", scopeOfFolderID(parent)); err != nil {
		return nil, err
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

// resolveParentFolder maps "" -> uuid.Nil (root); a uuid or DNS dotted path -> a
// folder id. Existence-hiding: an unknown ref OR a folder the caller has no
// relationship to (cannot manage and whose subtree holds no visible asset) both
// return NotFound, so a caller cannot probe folder existence.
func (s *CatalogServer) resolveParentFolder(ctx context.Context, userID uuid.UUID, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, nil // root: always browsable, contents are visibility-filtered
	}
	var id uuid.UUID
	if pid, perr := uuid.Parse(ref); perr == nil {
		f, err := s.q.GetFolder(ctx, pid)
		if err != nil {
			return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
		id = f.ID
	} else {
		fid, err := resolveFolderIDByPath(ctx, s.q, ref)
		if err != nil {
			return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
		id = fid
	}
	// visibility gate: manageable OR subtree has a visible asset (covers catalog:asset:read too,
	// since VisibleAssetsUnder's manage arm includes asset-read-covered assets).
	caps, err := s.authorizer.CapabilitiesOnScope(ctx, userID, authz.FolderScope(id))
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	if caps.Allows("catalog:folder:read") {
		return id, nil
	}
	assets, err := s.authorizer.VisibleAssetsUnder(ctx, userID, id, true)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(assets) > 0 {
		return id, nil
	}
	// Third arm: the caller can see a descendant folder (e.g. holds
	// catalog:folder:read bound below this node). VisibleFoldersUnder with
	// cascade=false returns direct children; we use cascade=false here because
	// if any child is visible (transitively) it will appear when the caller
	// browses. This aligns the gate with ListFolders' own visibility predicate.
	folders, err := s.authorizer.VisibleFoldersUnder(ctx, userID, id, false)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(folders) > 0 {
		return id, nil
	}
	return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
}

// ListFolders browses folders under a parent (default root), returning only the
// folders the caller may see — those they can manage or whose subtree holds an
// asset they can reach. Not cap-gated: an unrelated caller sees an empty page, not
// an error. Cascade descends the whole subtree; otherwise only direct children.
func (s *CatalogServer) ListFolders(ctx context.Context, req *connect.Request[catalogv1.ListFoldersRequest]) (*connect.Response[catalogv1.ListFoldersResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	parent, err := s.resolveParentFolder(ctx, u.ID, req.Msg.Parent)
	if err != nil {
		return nil, err
	}
	ids, err := s.authorizer.VisibleFoldersUnder(ctx, u.ID, parent, req.Msg.Cascade)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListFoldersResponse{}
	if len(ids) == 0 {
		return connect.NewResponse(out), nil
	}
	limit := clampPageSize(req.Msg.PageSize)
	key, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListFoldersByIDsPagedParams{Ids: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgText(key.Name)
		params.AfterID = pgUUID(key.ID)
	}
	rows, err := s.q.ListFoldersByIDsPaged(ctx, params)
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
	for i := range rows {
		m := toFolderMsg(rows[i])
		m.Path = pathByID[rows[i].ID.String()]
		out.Folders = append(out.Folders, m)
	}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Name, last.ID)
	}
	return connect.NewResponse(out), nil
}

// CreateAsset creates an asset in a folder (admin only). The asset row, its
// catalog_names entry, and any inline SSH config are written in one transaction.
func (s *CatalogServer) CreateAsset(ctx context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	fid, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	if err := s.requireCap(ctx, "catalog:asset:create", authz.FolderScope(fid)); err != nil {
		return nil, err
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
	id, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(id)); err != nil {
		return nil, err
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

// GetAssetDisplay returns an asset's decision context without secret references.
// TEMPORARY stub — real impl in a later task.
func (s *CatalogServer) GetAssetDisplay(_ context.Context, _ *connect.Request[catalogv1.GetAssetDisplayRequest]) (*connect.Response[catalogv1.GetAssetDisplayResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

// UpdateAssetConfig upserts an asset's typed config (admin only). The
// stored_key_needs_secret CHECK and the stored_secret_id FK surface as
// InvalidArgument.
func (s *CatalogServer) UpdateAssetConfig(ctx context.Context, req *connect.Request[catalogv1.UpdateAssetConfigRequest]) (*connect.Response[catalogv1.UpdateAssetConfigResponse], error) {
	assetID, err := uuid.Parse(req.Msg.AssetId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad asset_id"))
	}
	if err := s.requireCap(ctx, "catalog:asset:update", authz.AssetScope(assetID)); err != nil {
		return nil, err
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

// ListAssets browses assets under a parent (default root), returning only the
// assets the caller may see — those they can manage or reach (active/requestable).
// Not cap-gated: an unrelated caller sees an empty page, not an error. With
// parent="" and cascade=true this is the caller's full visible-asset catalog;
// cascade descends the whole subtree, otherwise only the parent's direct assets.
func (s *CatalogServer) ListAssets(ctx context.Context, req *connect.Request[catalogv1.ListAssetsRequest]) (*connect.Response[catalogv1.ListAssetsResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	parent, err := s.resolveParentFolder(ctx, u.ID, req.Msg.Parent)
	if err != nil {
		return nil, err
	}
	ids, err := s.authorizer.VisibleAssetsUnder(ctx, u.ID, parent, req.Msg.Cascade)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &catalogv1.ListAssetsResponse{}
	if len(ids) == 0 {
		return connect.NewResponse(out), nil
	}
	limit := clampPageSize(req.Msg.PageSize)
	key, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListAssetsByIDsPagedParams{Ids: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgText(key.Name)
		params.AfterID = pgUUID(key.ID)
	}
	rows, err := s.q.ListAssetsByIDsPaged(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	pathByFolder := map[uuid.UUID]string{}
	for i := range rows {
		m := toAssetMsg(rows[i])
		fp, ok := pathByFolder[rows[i].FolderID]
		if !ok {
			if fp, err = s.q.FolderPath(ctx, rows[i].FolderID); err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			pathByFolder[rows[i].FolderID] = fp
		}
		m.Path = joinPath(fp, rows[i].Name)
		out.Assets = append(out.Assets, m)
	}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Name, last.ID)
	}
	return connect.NewResponse(out), nil
}

// ResolveAsset maps a uuid or DNS-style dotted path to an asset id, but only for an
// asset the caller can reach. Unknown-ref and no-access both return NotFound
// (existence hiding). The response path is the canonical DNS path.
func (s *CatalogServer) ResolveAsset(ctx context.Context, req *connect.Request[catalogv1.ResolveAssetRequest]) (*connect.Response[catalogv1.ResolveAssetResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	ref := req.Msg.Ref

	var assetID, folderID uuid.UUID
	var assetName string
	if id, perr := uuid.Parse(ref); perr == nil {
		a, err := s.q.GetAsset(ctx, id)
		if err != nil {
			return nil, notFoundOrInternal(err)
		}
		assetID, folderID, assetName = a.ID, a.FolderID, a.Name
	} else {
		segs := strings.Split(ref, ".")
		if len(segs) < 2 {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
		}
		name := segs[0]
		var parent pgtype.UUID // NULL = top level
		var fid uuid.UUID
		for i := len(segs) - 1; i >= 1; i-- { // walk root→leaf (segs reversed: leaf is segs[0])
			f, err := s.q.FolderByParentName(ctx, gen.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
			if err != nil {
				return nil, notFoundOrInternal(err)
			}
			fid = f.ID
			parent = pgUUID(f.ID)
		}
		a, err := s.q.AssetByFolderName(ctx, gen.AssetByFolderNameParams{FolderID: fid, Name: name})
		if err != nil {
			return nil, notFoundOrInternal(err)
		}
		assetID, folderID, assetName = a.ID, a.FolderID, a.Name
	}

	// Access + existence hiding. The management read cap bypasses the data-plane
	// visibility gate (admins hold ** so this stays a no-op for them). Callers
	// without it are gated by a targeted single-asset RolesOnAsset lookup — same
	// visibility as VisibleAssets (active OR requestable) without enumerating a list.
	mgmtOK := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(assetID)) == nil
	if !mgmtOK {
		roles, err := s.authorizer.RolesOnAsset(ctx, u.ID, assetID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(roles.Active) == 0 && len(roles.Requestable) == 0 {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
		}
	}

	fp, err := s.q.FolderPath(ctx, folderID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.ResolveAssetResponse{
		AssetId: assetID.String(),
		Path:    joinPath(fp, assetName),
	}), nil
}

// ResolveFolder maps a uuid or DNS-style dotted path to a folder id. Admin only;
// unknown-ref returns NotFound. The response path is the canonical DNS path.
func (s *CatalogServer) ResolveFolder(ctx context.Context, req *connect.Request[catalogv1.ResolveFolderRequest]) (*connect.Response[catalogv1.ResolveFolderResponse], error) {
	ref := req.Msg.Ref

	var folderID uuid.UUID
	if id, perr := uuid.Parse(ref); perr == nil {
		f, err := s.q.GetFolder(ctx, id)
		if err != nil {
			return nil, folderNotFoundOrInternal(err)
		}
		folderID = f.ID
	} else {
		// Every segment is a folder; walk the shared leaf->root path resolver.
		id, err := resolveFolderIDByPath(ctx, s.q, ref)
		if err != nil {
			return nil, folderNotFoundOrInternal(err)
		}
		folderID = id
	}

	// Gate on the resolved folder's scope (resolve-then-check). A caller without
	// the read cap must not be able to distinguish an existing-but-invisible folder
	// from a nonexistent one, so a denial is reported as NotFound (existence hiding,
	// matching ResolveAsset) rather than PermissionDenied.
	if s.requireCap(ctx, "catalog:folder:read", authz.FolderScope(folderID)) != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}

	fp, err := s.q.FolderPath(ctx, folderID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.ResolveFolderResponse{
		FolderId: folderID.String(),
		Path:     fp,
	}), nil
}

// folderNotFoundOrInternal maps pgx.ErrNoRows to NotFound and any other error to Internal.
func folderNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// notFoundOrInternal maps pgx.ErrNoRows to NotFound (existence hiding) and any other
// error to Internal.
func notFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	return connect.NewError(connect.CodeInternal, err)
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
	// The management read cap bypasses the data-plane visibility gate (admins
	// hold ** so this stays a no-op for them). Callers without it get the
	// existence-hiding NotFound when they have no roles on the asset.
	mgmtOK := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(id)) == nil
	if !mgmtOK && len(roles.Active) == 0 && len(roles.Requestable) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
	}
	resp := &catalogv1.GetAssetAccessResponse{}
	for _, r := range roles.Active {
		resp.ActiveRoleIds = append(resp.ActiveRoleIds, r.String())
	}
	for _, r := range roles.Requestable {
		resp.RequestableRoleIds = append(resp.RequestableRoleIds, r.String())
	}
	if resp.ActiveRoles, err = roleRefs(ctx, s.q, roles.Active); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if resp.RequestableRoles, err = roleRefs(ctx, s.q, roles.Requestable); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	caps, err := s.authorizer.CapabilitiesOnAsset(ctx, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp.Capabilities = []string(caps)
	return connect.NewResponse(resp), nil
}

// contentsSlice is the bounded first-slice size returned by ListFolderContents.
const contentsSlice = 50

// ListFolderContents returns the first bounded slice (contentsSlice items per
// kind) of folders, assets, roles, and groups visible to the caller directly
// under the named parent folder (default root). has_more flags indicate whether
// additional items exist beyond the returned slice; callers wanting full
// pagination should use the dedicated per-kind List RPCs.
//
// The parent is existence-gated via resolveParentFolder (same as ListAssets /
// ListFolders), so an unknown or invisible parent returns NotFound. Cascade is
// intentionally false: only direct children are aggregated here.
func (s *CatalogServer) ListFolderContents(ctx context.Context, req *connect.Request[catalogv1.ListFolderContentsRequest]) (*connect.Response[catalogv1.ListFolderContentsResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	parent, err := s.resolveParentFolder(ctx, u.ID, req.Msg.Parent)
	if err != nil {
		return nil, err
	}

	out := &catalogv1.ListFolderContentsResponse{}

	// ── folders ───────────────────────────────────────────────────────────────
	folderIDs, err := s.authorizer.VisibleFoldersUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(folderIDs) > 0 {
		rows, err := s.q.ListFoldersByIDsPaged(ctx, gen.ListFoldersByIDsPagedParams{
			Ids: folderIDs,
			Lim: contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.FoldersHasMore = true
			rows = rows[:contentsSlice]
		}
		allPaths, err := s.q.FolderPaths(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		pathByID := make(map[string]string, len(allPaths))
		for _, p := range allPaths {
			pathByID[p.ID.String()] = p.Path
		}
		for i := range rows {
			m := toFolderMsg(rows[i])
			m.Path = pathByID[rows[i].ID.String()]
			out.Folders = append(out.Folders, m)
		}
	}

	// ── assets ────────────────────────────────────────────────────────────────
	assetIDs, err := s.authorizer.VisibleAssetsUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(assetIDs) > 0 {
		rows, err := s.q.ListAssetsByIDsPaged(ctx, gen.ListAssetsByIDsPagedParams{
			Ids: assetIDs,
			Lim: contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.AssetsHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			m := toAssetMsg(rows[i])
			fp, ok := pathByFolder[rows[i].FolderID]
			if !ok {
				if fp, err = s.q.FolderPath(ctx, rows[i].FolderID); err != nil {
					return nil, connect.NewError(connect.CodeInternal, err)
				}
				pathByFolder[rows[i].FolderID] = fp
			}
			m.Path = joinPath(fp, rows[i].Name)
			out.Assets = append(out.Assets, m)
		}
	}

	// ── roles ─────────────────────────────────────────────────────────────────
	roleIDs, err := s.authorizer.VisibleRolesUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(roleIDs) > 0 {
		rows, err := s.q.ListRolesByIDsPaged(ctx, gen.ListRolesByIDsPagedParams{
			Column1: roleIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.RolesHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			m := toAccessRoleMsg(rows[i])
			if rows[i].FolderID.Valid {
				fid := uuidFromPg(rows[i].FolderID)
				p, ok := pathByFolder[fid]
				if !ok {
					if p, err = s.q.FolderPath(ctx, fid); err != nil {
						return nil, connect.NewError(connect.CodeInternal, err)
					}
					pathByFolder[fid] = p
				}
				m.FolderPath = p
			}
			out.Roles = append(out.Roles, m)
		}
	}

	// ── groups ────────────────────────────────────────────────────────────────
	groupIDs, err := s.authorizer.VisibleGroupsUnder(ctx, u.ID, parent, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(groupIDs) > 0 {
		rows, err := s.q.ListGroupsByIDsPaged(ctx, gen.ListGroupsByIDsPagedParams{
			Column1: groupIDs,
			Lim:     contentsSlice + 1,
		})
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(rows) > contentsSlice {
			out.GroupsHasMore = true
			rows = rows[:contentsSlice]
		}
		pathByFolder := map[uuid.UUID]string{}
		for i := range rows {
			m := toGroupMsg(rows[i])
			if rows[i].FolderID.Valid {
				fid := uuidFromPg(rows[i].FolderID)
				p, ok := pathByFolder[fid]
				if !ok {
					if p, err = s.q.FolderPath(ctx, fid); err != nil {
						return nil, connect.NewError(connect.CodeInternal, err)
					}
					pathByFolder[fid] = p
				}
				m.FolderPath = p
			}
			out.Groups = append(out.Groups, m)
		}
	}

	return connect.NewResponse(out), nil
}

// GetFolderAccess returns the caller's management capabilities on one folder;
// NotFound (existence hiding) if the caller has no relationship to it — neither
// a capability on its scope nor a visible asset in its subtree.
func (s *CatalogServer) GetFolderAccess(ctx context.Context, req *connect.Request[catalogv1.GetFolderAccessRequest]) (*connect.Response[catalogv1.GetFolderAccessResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	id, err := uuid.Parse(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	caps, err := s.authorizer.CapabilitiesOnScope(ctx, u.ID, authz.FolderScope(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		assets, err := s.authorizer.VisibleAssetsUnder(ctx, u.ID, id, true)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(assets) == 0 {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
	}
	return connect.NewResponse(&catalogv1.GetFolderAccessResponse{Capabilities: []string(caps)}), nil
}
