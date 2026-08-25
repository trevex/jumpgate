package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	gossh "golang.org/x/crypto/ssh"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

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
func toAssetMsgWithConfig(a sqlc.Asset, cfg sqlc.SshAssetConfig, logins []sqlc.SshAssetLogin) *catalogv1.Asset {
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

// validateSSHConfigInput checks the parts protovalidate can't: an optional
// host_public_key must be a parseable authorized_keys line, and login names must be
// unique within the config (a duplicate would silently collapse under the
// (asset_id, login) upsert conflict).
func validateSSHConfigInput(in *catalogv1.SSHConfigInput) error {
	if in.GetHostPublicKey() != "" {
		if _, _, _, _, err := gossh.ParseAuthorizedKey([]byte(in.GetHostPublicKey())); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad host_public_key"))
		}
	}
	seen := make(map[string]struct{}, len(in.GetLogins()))
	for _, l := range in.GetLogins() {
		if _, dup := seen[l.GetLogin()]; dup {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("duplicate login "+l.GetLogin()))
		}
		seen[l.GetLogin()] = struct{}{}
	}
	return nil
}

// CreateAsset creates an asset in a folder (admin only). The asset row, its
// catalog_names entry, and its inline SSH config — including any inline login
// secrets, sealed in place — are written in one transaction. The asset kind is
// derived server-side from the config oneof arm (currently always "ssh").
func (s *CatalogServer) CreateAsset(ctx context.Context, req *connect.Request[catalogv1.CreateAssetRequest]) (*connect.Response[catalogv1.CreateAssetResponse], error) {
	fid, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	if err := s.requireCap(ctx, "catalog:asset:create", authz.FolderScope(fid)); err != nil {
		return nil, err
	}
	sshIn := req.Msg.GetSsh()
	if sshIn == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("config required"))
	}
	if err := validateSSHConfigInput(sshIn); err != nil {
		return nil, err
	}
	name := strings.ToLower(req.Msg.GetName())

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	a, err := qtx.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: fid, Name: name, Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		return nil, mapWriteErr(err) // a bad folder_id is InvalidArgument, not Internal
	}
	if err := qtx.InsertAssetName(ctx, sqlc.InsertAssetNameParams{ParentID: pgUUID(a.FolderID), Name: name, AssetID: pgUUID(a.ID)}); err != nil {
		return nil, mapWriteErr(err) // sibling collision (incl. vs a folder) -> AlreadyExists
	}

	rows, err := s.resolveSSHConfigInput(ctx, qtx, a.ID, sshIn, true)
	if err != nil {
		return nil, err
	}
	if err := writeSSHConfig(ctx, qtx, a.ID, sshIn.GetHostPublicKey(), sshIn.GetTargetAddress(), rows); err != nil {
		return nil, mapWriteErr(err) // CHECK / composite-FK → InvalidArgument
	}
	cfg, err := qtx.GetSSHAssetConfig(ctx, a.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
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
	sshIn := req.Msg.GetSsh()
	if sshIn == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("config required"))
	}
	if err := validateSSHConfigInput(sshIn); err != nil {
		return nil, err
	}
	// The asset must exist (existence check, matching GetAsset's NotFound contract).
	if _, err := s.q.GetAsset(ctx, assetID); err != nil {
		return nil, notFoundOrInternal(err)
	}
	// Seal inline secrets, upsert the connection config, replace the login set, and
	// prune any now-orphaned secrets — all atomically.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)
	rows, err := s.resolveSSHConfigInput(ctx, qtx, assetID, sshIn, false)
	if err != nil {
		return nil, err
	}
	if err := writeSSHConfig(ctx, qtx, assetID, sshIn.GetHostPublicKey(), sshIn.GetTargetAddress(), rows); err != nil {
		return nil, mapWriteErr(err) // CHECK / composite-FK → InvalidArgument
	}
	if err := qtx.DeleteOrphanSecretsForAsset(ctx, assetID); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
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
	params := sqlc.ListAssetsByIDsPagedParams{Ids: ids, Lim: limit}
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
			f, err := s.q.FolderByParentName(ctx, sqlc.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
			if err != nil {
				return nil, notFoundOrInternal(err)
			}
			fid = f.ID
			parent = pgUUID(f.ID)
		}
		a, err := s.q.AssetByFolderName(ctx, sqlc.AssetByFolderNameParams{FolderID: fid, Name: name})
		if err != nil {
			return nil, notFoundOrInternal(err)
		}
		assetID, folderID, assetName = a.ID, a.FolderID, a.Name
	}

	// Access + existence hiding. The management read cap bypasses the data-plane
	// visibility gate (admins hold ** so this stays a no-op for them). Callers
	// without it are gated by a targeted single-asset RolesOnAsset lookup — same
	// visibility as VisibleAssets (active OR requestable) without enumerating a list —
	// OR the CONNECT arm: a folder/global ssh:login cascade entitling ≥1 of the
	// asset's own logins (authz.AssetVisible), so a folder-scoped ssh:login binding
	// surfaces its asset without any asset-scoped role or catalog:asset:read.
	mgmtOK := s.requireCap(ctx, "catalog:asset:read", authz.AssetScope(assetID)) == nil
	if !mgmtOK {
		roles, err := s.authorizer.RolesOnAsset(ctx, u.ID, assetID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if len(roles.Active) == 0 && len(roles.Requestable) == 0 {
			visible, err := authz.AssetVisible(ctx, s.authorizer, u.ID, assetID)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			if !visible {
				return nil, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
			}
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

// DeleteAsset removes an asset and everything about it: its secrets, logins,
// asset-scoped bindings/policies, and live sessions. Session teardown is signalled
// FIRST (while the rows still exist), then the rows are deleted in the RESTRICT-safe
// order (logins before secrets) in one tx.
func (s *CatalogServer) DeleteAsset(ctx context.Context, req *connect.Request[catalogv1.DeleteAssetRequest]) (*connect.Response[catalogv1.DeleteAssetResponse], error) {
	id, err := uuid.Parse(req.Msg.GetAssetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid asset_id"))
	}
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	visible, err := authz.AssetVisible(ctx, s.authorizer, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !visible {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	if err := s.requireCap(ctx, "catalog:asset:delete", authz.AssetScope(id)); err != nil {
		return nil, err
	}
	// Signal teardown while live_sessions rows still exist.
	if s.terminator != nil {
		if err := s.terminator.TerminateAssetSessions(ctx, id); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	// RESTRICT-safe order: logins reference secrets, so drop logins first.
	if err := q.DeleteSSHAssetLoginsForAsset(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteAssetSecretsForAsset(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteRoleBindingsForAsset(ctx, pgUUID(id)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeletePolicySubjectsForAsset(ctx, pgUUID(id)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteRequestPoliciesForAsset(ctx, pgUUID(id)); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteAsset(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.DeleteAssetResponse{}), nil
}

// UpdateAsset renames and/or moves an asset. A rename rewrites the asset row and its
// catalog_names entry (sibling collision → AlreadyExists). A move re-validates
// containment (FailedPrecondition if it would strand a folder-scoped role granted by
// a binding/policy on this asset), then rewrites folder_id and fires authz_changed so
// the sweeper tears down any now-disallowed live sessions. Existence-hidden.
func (s *CatalogServer) UpdateAsset(ctx context.Context, req *connect.Request[catalogv1.UpdateAssetRequest]) (*connect.Response[catalogv1.UpdateAssetResponse], error) {
	id, err := uuid.Parse(req.Msg.GetAssetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid asset_id"))
	}
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	visible, err := authz.AssetVisible(ctx, s.authorizer, u.ID, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !visible {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	if err := s.requireCap(ctx, "catalog:asset:update", authz.AssetScope(id)); err != nil {
		return nil, err
	}
	cur, err := s.q.GetAsset(ctx, id)
	if err != nil {
		return nil, notFoundOrInternal(err)
	}
	newName := cur.Name
	newFolder := cur.FolderID // assets.folder_id is NOT NULL (uuid.UUID)
	moving := false
	if req.Msg.Name != nil {
		newName = strings.ToLower(req.Msg.GetName())
	}
	if req.Msg.FolderId != nil {
		f, err := uuid.Parse(req.Msg.GetFolderId())
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
		}
		if f != newFolder {
			// Creating the asset in its new home requires create there.
			if err := s.requireCap(ctx, "catalog:asset:create", authz.FolderScope(f)); err != nil {
				return nil, err
			}
			newFolder, moving = f, true
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if moving {
		if err := s.validateAssetMove(ctx, q, id, newFolder); err != nil {
			return nil, err
		}
		if err := q.UpdateAssetFolder(ctx, sqlc.UpdateAssetFolderParams{ID: id, FolderID: newFolder}); err != nil {
			return nil, mapWriteErr(err)
		}
	}
	if newName != cur.Name || moving {
		if err := q.UpdateAssetName(ctx, sqlc.UpdateAssetNameParams{ID: id, Name: newName}); err != nil {
			return nil, mapWriteErr(err)
		}
		if err := q.UpdateAssetCatalogName(ctx, sqlc.UpdateAssetCatalogNameParams{AssetID: pgUUID(id), ParentID: pgUUID(newFolder), Name: newName}); err != nil {
			return nil, mapWriteErr(err) // sibling collision (incl. vs a folder) -> AlreadyExists
		}
	}
	if moving {
		if err := q.NotifyAuthzChanged(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.UpdateAssetResponse{Asset: s.assetMsgWithPath(ctx, toAssetMsg(a), a.FolderID, a.Name)}), nil
}
