package rpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

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

	f, err := qtx.CreateFolder(ctx, sqlc.CreateFolderParams{Name: name, ParentID: parent})
	if err != nil {
		return nil, mapWriteErr(err) // a bad parent_id is InvalidArgument, not Internal
	}
	if err := qtx.InsertFolderName(ctx, sqlc.InsertFolderNameParams{ParentID: parent, Name: name, FolderID: pgUUID(f.ID)}); err != nil {
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
	if len(authz.FolderIDsOf(folders)) > 0 {
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
	visible, err := s.authorizer.VisibleFoldersUnder(ctx, u.ID, parent, req.Msg.Cascade)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	govByID := make(map[uuid.UUID]bool, len(visible))
	for _, vf := range visible {
		govByID[vf.ID] = vf.Governed
	}
	ids := authz.FolderIDsOf(visible)
	out := &catalogv1.ListFoldersResponse{}
	if len(ids) == 0 {
		return connect.NewResponse(out), nil
	}
	limit := clampPageSize(req.Msg.PageSize)
	key, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := sqlc.ListFoldersByIDsPagedParams{Ids: ids, Lim: limit}
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
		m.Governed = govByID[rows[i].ID]
		out.Folders = append(out.Folders, m)
	}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Name, last.ID)
	}
	return connect.NewResponse(out), nil
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

// DeleteFolder removes a folder only if nothing references it — child folders/assets,
// folder-scoped roles/groups homed in it, or bindings/policies scoped to it. It lists
// the blockers rather than cascading (the DB FKs are ON DELETE CASCADE, refused here).
func (s *CatalogServer) DeleteFolder(ctx context.Context, req *connect.Request[catalogv1.DeleteFolderRequest]) (*connect.Response[catalogv1.DeleteFolderResponse], error) {
	id, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
	}
	// Existence-hide: a caller who can't read it sees NotFound; then require delete.
	if s.requireCap(ctx, "catalog:folder:read", authz.FolderScope(id)) != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	if err := s.requireCap(ctx, "catalog:folder:delete", authz.FolderScope(id)); err != nil {
		return nil, err
	}

	// Count every referencing relation. Signatures differ: assets.folder_id is NOT
	// NULL (uuid.UUID); the rest are nullable (pgtype.UUID) — so call each directly.
	var blockers []string
	appendBlocker := func(n int64, label string) {
		if n > 0 {
			blockers = append(blockers, fmt.Sprintf("%d %s", n, label))
		}
	}
	nChildFolders, err := s.q.CountChildFolders(ctx, pgUUID(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nChildFolders, "child folders")
	nAssets, err := s.q.CountAssetsInFolder(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nAssets, "assets")
	nRoles, err := s.q.CountRolesHomedInFolder(ctx, pgUUID(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nRoles, "roles homed here")
	nGroups, err := s.q.CountGroupsHomedInFolder(ctx, pgUUID(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nGroups, "groups homed here")
	nBindings, err := s.q.CountBindingsScopedToFolder(ctx, pgUUID(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nBindings, "bindings scoped here")
	nPolicies, err := s.q.CountPoliciesScopedToFolder(ctx, pgUUID(id))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nPolicies, "policies scoped here")

	if len(blockers) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("folder not empty: %s", strings.Join(blockers, ", ")))
	}
	if err := s.q.DeleteFolder(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&catalogv1.DeleteFolderResponse{}), nil
}

// UpdateFolder renames and/or reparents a folder. A rename rewrites the folder row
// and its catalog_names entry (sibling collision → AlreadyExists). A move guards
// against a cycle (reparenting under a descendant → FailedPrecondition), re-validates
// containment for every binding/policy in the moved subtree (FailedPrecondition if it
// would strand a folder-scoped role), then rewrites parent_id and fires authz_changed.
// A ParentId of "" moves the folder to the root. Existence-hidden.
func (s *CatalogServer) UpdateFolder(ctx context.Context, req *connect.Request[catalogv1.UpdateFolderRequest]) (*connect.Response[catalogv1.UpdateFolderResponse], error) {
	id, err := uuid.Parse(req.Msg.GetFolderId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid folder_id"))
	}
	// Existence-hide: a caller who can't read it sees NotFound; then require update.
	if s.requireCap(ctx, "catalog:folder:read", authz.FolderScope(id)) != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	if err := s.requireCap(ctx, "catalog:folder:update", authz.FolderScope(id)); err != nil {
		return nil, err
	}
	cur, err := s.q.GetFolder(ctx, id)
	if err != nil {
		return nil, folderNotFoundOrInternal(err)
	}

	newName := cur.Name
	if req.Msg.Name != nil {
		newName = strings.ToLower(req.Msg.GetName())
	}
	newParent := cur.ParentID // pgtype.UUID; NULL = root
	moving := false
	if req.Msg.ParentId != nil {
		if req.Msg.GetParentId() == "" {
			if cur.ParentID.Valid { // only a change if it isn't already root
				newParent, moving = pgtype.UUID{}, true
			}
		} else {
			pid, err := uuid.Parse(req.Msg.GetParentId())
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid parent_id"))
			}
			if !cur.ParentID.Valid || uuid.UUID(cur.ParentID.Bytes) != pid {
				// Placing the folder under its new parent requires create there.
				if err := s.requireCap(ctx, "catalog:folder:create", authz.FolderScope(pid)); err != nil {
					return nil, err
				}
				newParent, moving = pgUUID(pid), true
			}
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if moving {
		// Cycle guard applies only to a real destination: the root can never lie
		// inside the moved subtree, so a root move needs no cycle check.
		if newParent.Valid {
			subList, err := q.FolderSubtreeIDs(ctx, id)
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal, err)
			}
			np := uuid.UUID(newParent.Bytes)
			for _, sid := range subList {
				if sid == np {
					return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot move a folder into its own subtree"))
				}
			}
		}
		// Re-validate containment for EVERY move, including a move to the root: a root
		// move narrows the ancestor set (drops everything above the folder), which can
		// strand a folder-scoped binding/policy in the subtree.
		if err := s.validateFolderMove(ctx, q, id, newParent); err != nil {
			return nil, err
		}
		if err := q.UpdateFolderParent(ctx, sqlc.UpdateFolderParentParams{ID: id, ParentID: newParent}); err != nil {
			return nil, mapWriteErr(err)
		}
	}
	if newName != cur.Name || moving {
		if err := q.UpdateFolderName(ctx, sqlc.UpdateFolderNameParams{ID: id, Name: newName}); err != nil {
			return nil, mapWriteErr(err)
		}
		if err := q.UpdateFolderCatalogName(ctx, sqlc.UpdateFolderCatalogNameParams{FolderID: pgUUID(id), ParentID: newParent, Name: newName}); err != nil {
			return nil, mapWriteErr(err) // sibling collision -> AlreadyExists
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

	f, err := s.q.GetFolder(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	msg := toFolderMsg(f)
	if path, perr := s.q.FolderPath(ctx, f.ID); perr == nil {
		msg.Path = path
	}
	return connect.NewResponse(&catalogv1.UpdateFolderResponse{Folder: msg}), nil
}

// folderNotFoundOrInternal maps pgx.ErrNoRows to NotFound and any other error to Internal.
func folderNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	return connect.NewError(connect.CodeInternal, err)
}
