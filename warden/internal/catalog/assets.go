package catalog

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// assetPath returns an asset's best-effort DNS path via a FolderPath lookup. On a
// lookup error the path is left empty rather than failing the caller (the asset is
// already committed / exists).
func (s *Service) assetPath(ctx context.Context, folderID uuid.UUID, name string) string {
	if fp, err := s.q.FolderPath(ctx, folderID); err == nil {
		return joinPath(fp, name)
	}
	return ""
}

// CreateAsset creates an asset in a folder. The asset row, its catalog_names entry,
// and its inline SSH config — including any inline login secrets, sealed in place —
// are written in one transaction. The asset kind is "ssh".
func (s *Service) CreateAsset(ctx context.Context, folderID uuid.UUID, name string, in SSHConfigInput) (AssetWithConfig, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	a, err := qtx.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folderID, Name: name, Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		return AssetWithConfig{}, apierr.MapWrite(err) // a bad folder_id is InvalidArgument, not Internal
	}
	if err := qtx.InsertAssetName(ctx, sqlc.InsertAssetNameParams{ParentID: pgconv.UUID(a.FolderID), Name: name, AssetID: pgconv.UUID(a.ID)}); err != nil {
		return AssetWithConfig{}, apierr.MapWrite(err) // sibling collision (incl. vs a folder) -> AlreadyExists
	}

	rows, err := s.resolveSSHConfigInput(ctx, qtx, a.ID, in, true)
	if err != nil {
		return AssetWithConfig{}, err
	}
	if err := writeSSHConfig(ctx, qtx, a.ID, in.HostPublicKey, in.TargetAddress, rows); err != nil {
		return AssetWithConfig{}, apierr.MapWrite(err) // CHECK / composite-FK → InvalidArgument
	}
	cfg, err := qtx.GetSSHAssetConfig(ctx, a.ID)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	logins, err := qtx.ListSSHAssetLogins(ctx, a.ID)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	return AssetWithConfig{Asset: a, Path: s.assetPath(ctx, a.FolderID, a.Name), Config: &cfg, Logins: logins}, nil
}

// GetAsset returns an asset with its typed config. NotFound if the asset does not
// exist; an asset with no ssh config returns a result with a nil Config.
func (s *Service) GetAsset(ctx context.Context, id uuid.UUID) (AssetWithConfig, error) {
	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AssetWithConfig{}, connect.NewError(connect.CodeNotFound, errors.New("asset not found"))
		}
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	res := AssetWithConfig{Asset: a, Path: s.assetPath(ctx, a.FolderID, a.Name)}
	cfg, err := s.q.GetSSHAssetConfig(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return res, nil
		}
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	logins, err := s.q.ListSSHAssetLogins(ctx, id)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	res.Config = &cfg
	res.Logins = logins
	return res, nil
}

// UpdateAssetConfig upserts an asset's typed config. The stored_key_needs_secret
// CHECK and the stored_secret_id FK surface as InvalidArgument.
func (s *Service) UpdateAssetConfig(ctx context.Context, assetID uuid.UUID, in SSHConfigInput) error {
	// The asset must exist (existence check, matching GetAsset's NotFound contract).
	if _, err := s.q.GetAsset(ctx, assetID); err != nil {
		return notFoundOrInternal(err)
	}
	// Seal inline secrets, upsert the connection config, replace the login set, and
	// prune any now-orphaned secrets — all atomically.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)
	rows, err := s.resolveSSHConfigInput(ctx, qtx, assetID, in, false)
	if err != nil {
		return err
	}
	if err := writeSSHConfig(ctx, qtx, assetID, in.HostPublicKey, in.TargetAddress, rows); err != nil {
		return apierr.MapWrite(err) // CHECK / composite-FK → InvalidArgument
	}
	if err := qtx.DeleteOrphanSecretsForAsset(ctx, assetID); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// ListAssets browses assets under a parent (default root), returning only the assets
// the caller may see — those they can manage or reach (active/requestable). Not
// cap-gated: an unrelated caller sees an empty page. With parentRef="" and
// cascade=true this is the caller's full visible-asset catalog. Returns the page rows
// and an opaque next-page token ("" when the page is not full).
func (s *Service) ListAssets(ctx context.Context, caller uuid.UUID, parentRef string, cascade bool, pageSize int32, pageToken string) ([]AssetRow, string, error) {
	parent, err := s.resolveParentFolder(ctx, caller, parentRef)
	if err != nil {
		return nil, "", err
	}
	ids, err := s.authz.VisibleAssetsUnder(ctx, caller, parent, cascade)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	if len(ids) == 0 {
		return nil, "", nil
	}
	limit := apipage.ClampPageSize(pageSize)
	key, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListAssetsByIDsPagedParams{Ids: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgconv.Text(key.Name)
		params.AfterID = pgconv.UUID(key.ID)
	}
	rows, err := s.q.ListAssetsByIDsPaged(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	out := make([]AssetRow, 0, len(rows))
	pathByFolder := map[uuid.UUID]string{}
	for i := range rows {
		fp, ok := pathByFolder[rows[i].FolderID]
		if !ok {
			if fp, err = s.q.FolderPath(ctx, rows[i].FolderID); err != nil {
				return nil, "", connect.NewError(connect.CodeInternal, err)
			}
			pathByFolder[rows[i].FolderID] = fp
		}
		out = append(out, AssetRow{Asset: rows[i], Path: joinPath(fp, rows[i].Name)})
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeNameToken(last.Name, last.ID)
	}
	return out, next, nil
}

// ResolveAsset maps a uuid or DNS-style dotted path to an asset id, but only for an
// asset the caller can reach. Unknown-ref and no-access both return NotFound
// (existence hiding). The response path is the canonical DNS path.
func (s *Service) ResolveAsset(ctx context.Context, caller uuid.UUID, ref string) (ResolveResult, error) {
	var assetID, folderID uuid.UUID
	var assetName string
	if id, perr := uuid.Parse(ref); perr == nil {
		a, err := s.q.GetAsset(ctx, id)
		if err != nil {
			return ResolveResult{}, notFoundOrInternal(err)
		}
		assetID, folderID, assetName = a.ID, a.FolderID, a.Name
	} else {
		segs := strings.Split(ref, ".")
		if len(segs) < 2 {
			return ResolveResult{}, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
		}
		name := segs[0]
		var parent pgtype.UUID // NULL = top level
		var fid uuid.UUID
		for i := len(segs) - 1; i >= 1; i-- { // walk root→leaf (segs reversed: leaf is segs[0])
			f, err := s.q.FolderByParentName(ctx, sqlc.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
			if err != nil {
				return ResolveResult{}, notFoundOrInternal(err)
			}
			fid = f.ID
			parent = pgconv.UUID(f.ID)
		}
		a, err := s.q.AssetByFolderName(ctx, sqlc.AssetByFolderNameParams{FolderID: fid, Name: name})
		if err != nil {
			return ResolveResult{}, notFoundOrInternal(err)
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
	mgmtOK := s.guard.RequireReadCap(ctx, caller, "catalog:asset:read", authz.AssetScope(assetID)) == nil
	if !mgmtOK {
		roles, err := s.authz.RolesOnAsset(ctx, caller, assetID)
		if err != nil {
			return ResolveResult{}, connect.NewError(connect.CodeInternal, err)
		}
		if len(roles.Active) == 0 && len(roles.Requestable) == 0 {
			visible, err := authz.AssetVisible(ctx, s.authz, caller, assetID)
			if err != nil {
				return ResolveResult{}, connect.NewError(connect.CodeInternal, err)
			}
			if !visible {
				return ResolveResult{}, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
			}
		}
	}

	fp, err := s.q.FolderPath(ctx, folderID)
	if err != nil {
		return ResolveResult{}, connect.NewError(connect.CodeInternal, err)
	}
	return ResolveResult{ID: assetID.String(), Path: joinPath(fp, assetName)}, nil
}

// DeleteAsset removes an asset and everything about it: its secrets, logins, and live
// sessions; asset-scoped bindings/policies cascade via DB FK. Session teardown is
// signalled FIRST (while the rows still exist), then the rows are deleted in the
// RESTRICT-safe order (logins before secrets) in one tx. Existence-hidden (NotFound)
// for an asset the caller cannot see.
func (s *Service) DeleteAsset(ctx context.Context, caller uuid.UUID, id uuid.UUID) error {
	visible, err := authz.AssetVisible(ctx, s.authz, caller, id)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !visible {
		return connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	if err := s.guard.RequireCap(ctx, caller, "catalog:asset:delete", authz.AssetScope(id)); err != nil {
		return err
	}
	// Signal teardown while live_sessions rows still exist.
	if s.terminator != nil {
		if err := s.terminator.TerminateAssetSessions(ctx, id); err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	// RESTRICT-safe order: logins reference secrets, so drop logins first. The
	// asset-scoped role_bindings/request_policies cascade via ON DELETE CASCADE.
	if err := q.DeleteSSHAssetLoginsForAsset(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteAssetSecretsForAsset(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := q.DeleteAsset(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// UpdateAssetInput carries the optional rename/move fields for UpdateAsset. A nil
// pointer means "leave unchanged"; the FolderID string is the destination folder id.
type UpdateAssetInput struct {
	Name     *string
	FolderID *string
}

// UpdateAsset renames and/or moves an asset. A rename rewrites the asset row and its
// catalog_names entry (sibling collision → AlreadyExists). A move re-validates
// containment (FailedPrecondition if it would strand a folder-scoped role granted by
// a binding/policy on this asset), then rewrites folder_id and fires authz_changed so
// the sweeper tears down any now-disallowed live sessions. Existence-hidden.
func (s *Service) UpdateAsset(ctx context.Context, caller uuid.UUID, id uuid.UUID, in UpdateAssetInput) (AssetWithConfig, error) {
	visible, err := authz.AssetVisible(ctx, s.authz, caller, id)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	if !visible {
		return AssetWithConfig{}, connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	if err := s.guard.RequireCap(ctx, caller, "catalog:asset:update", authz.AssetScope(id)); err != nil {
		return AssetWithConfig{}, err
	}
	cur, err := s.q.GetAsset(ctx, id)
	if err != nil {
		return AssetWithConfig{}, notFoundOrInternal(err)
	}
	newName := cur.Name
	newFolder := cur.FolderID // assets.folder_id is NOT NULL (uuid.UUID)
	moving := false
	if in.Name != nil {
		newName = strings.ToLower(*in.Name)
	}
	if in.FolderID != nil {
		f, err := uuid.Parse(*in.FolderID)
		if err != nil {
			return AssetWithConfig{}, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
		}
		if f != newFolder {
			// Creating the asset in its new home requires create there.
			if err := s.guard.RequireCap(ctx, caller, "catalog:asset:create", authz.FolderScope(f)); err != nil {
				return AssetWithConfig{}, err
			}
			newFolder, moving = f, true
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if moving {
		if err := s.validateAssetMove(ctx, q, id, newFolder); err != nil {
			return AssetWithConfig{}, err
		}
		if err := q.UpdateAssetFolder(ctx, sqlc.UpdateAssetFolderParams{ID: id, FolderID: newFolder}); err != nil {
			return AssetWithConfig{}, apierr.MapWrite(err)
		}
	}
	if newName != cur.Name || moving {
		if err := q.UpdateAssetName(ctx, sqlc.UpdateAssetNameParams{ID: id, Name: newName}); err != nil {
			return AssetWithConfig{}, apierr.MapWrite(err)
		}
		if err := q.UpdateAssetCatalogName(ctx, sqlc.UpdateAssetCatalogNameParams{AssetID: pgconv.UUID(id), ParentID: pgconv.UUID(newFolder), Name: newName}); err != nil {
			return AssetWithConfig{}, apierr.MapWrite(err) // sibling collision (incl. vs a folder) -> AlreadyExists
		}
	}
	if moving {
		if err := q.NotifyAuthzChanged(ctx); err != nil {
			return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}

	a, err := s.q.GetAsset(ctx, id)
	if err != nil {
		return AssetWithConfig{}, connect.NewError(connect.CodeInternal, err)
	}
	return AssetWithConfig{Asset: a, Path: s.assetPath(ctx, a.FolderID, a.Name)}, nil
}
