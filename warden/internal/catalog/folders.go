package catalog

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// resolveFolderIDByPath walks a DNS-style leaf->root folder path (e.g. "db.prod") to
// a folder id, matching root->leaf. Returns pgx.ErrNoRows if any segment is missing
// so callers can map it to NotFound.
func resolveFolderIDByPath(ctx context.Context, q *sqlc.Queries, path string) (uuid.UUID, error) {
	segs := strings.Split(path, ".")
	var parent pgtype.UUID // NULL = top level
	var folderID uuid.UUID
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := q.FolderByParentName(ctx, sqlc.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
		if err != nil {
			return uuid.Nil, err
		}
		folderID = f.ID
		parent = pgconv.UUID(f.ID)
	}
	return folderID, nil
}

// CreateFolder creates a folder. The folder row and its catalog_names entry are
// written in one transaction so sibling uniqueness is enforced atomically.
func (s *Service) CreateFolder(ctx context.Context, parent pgtype.UUID, name string) (FolderResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return FolderResult{}, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	// CreateFolder registers the catalog_names entry atomically, so a bad parent_id is
	// InvalidArgument and a sibling collision is AlreadyExists.
	f, err := qtx.CreateFolder(ctx, sqlc.CreateFolderParams{Name: name, ParentID: parent})
	if err != nil {
		return FolderResult{}, mapWrite(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return FolderResult{}, connect.NewError(connect.CodeInternal, err)
	}

	res := FolderResult{Folder: f}
	if path, err := s.q.FolderPath(ctx, f.ID); err == nil {
		res.Path = path
	}
	return res, nil
}

// resolveParentFolder maps "" -> uuid.Nil (root); a uuid or DNS dotted path -> a
// folder id. Existence-hiding: an unknown ref OR a folder the caller has no
// relationship to (cannot manage and whose subtree holds no visible asset) both
// return NotFound, so a caller cannot probe folder existence.
func (s *Service) resolveParentFolder(ctx context.Context, userID uuid.UUID, ref string) (uuid.UUID, error) {
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
	caps, err := s.authz.CapabilitiesOnScope(ctx, userID, authz.FolderScope(id))
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	if caps.Allows("catalog:folder:read") {
		return id, nil
	}
	assets, err := s.authz.VisibleAssetsUnder(ctx, userID, id, true)
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
	folders, err := s.authz.VisibleFoldersUnder(ctx, userID, id, false)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(authz.FolderIDsOf(folders)) > 0 {
		return id, nil
	}
	return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
}

// ListFolders browses folders under a parent (default root), returning only the
// folders the caller may see — those they can manage or whose subtree holds an asset
// they can reach. Not cap-gated. Returns the page rows and an opaque next-page token.
func (s *Service) ListFolders(ctx context.Context, caller uuid.UUID, parentRef string, cascade bool, pageSize int32, pageToken string) ([]FolderRow, string, error) {
	parent, err := s.resolveParentFolder(ctx, caller, parentRef)
	if err != nil {
		return nil, "", err
	}
	visible, err := s.authz.VisibleFoldersUnder(ctx, caller, parent, cascade)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	govByID := make(map[uuid.UUID]bool, len(visible))
	for _, vf := range visible {
		govByID[vf.ID] = vf.Governed
	}
	ids := authz.FolderIDsOf(visible)
	if len(ids) == 0 {
		return nil, "", nil
	}
	limit := apipage.ClampPageSize(pageSize)
	key, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListFoldersByIDsPagedParams{Ids: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgconv.Text(key.Name)
		params.AfterID = pgconv.UUID(key.ID)
	}
	rows, err := s.q.ListFoldersByIDsPaged(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	allPaths, err := s.q.FolderPaths(ctx)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	pathByID := make(map[string]string, len(allPaths))
	for _, p := range allPaths {
		pathByID[p.ID.String()] = p.Path
	}
	out := make([]FolderRow, 0, len(rows))
	for i := range rows {
		out = append(out, FolderRow{Folder: rows[i], Path: pathByID[rows[i].ID.String()], Governed: govByID[rows[i].ID]})
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeNameToken(last.Name, last.ID)
	}
	return out, next, nil
}

// ResolveFolder maps a uuid or DNS-style dotted path to a folder id. Resolve-then-
// check: a caller without catalog:folder:read on the resolved folder gets NotFound
// (existence hiding, matching ResolveAsset). The response path is the canonical DNS path.
func (s *Service) ResolveFolder(ctx context.Context, caller uuid.UUID, ref string) (ResolveResult, error) {
	var folderID uuid.UUID
	if id, perr := uuid.Parse(ref); perr == nil {
		f, err := s.q.GetFolder(ctx, id)
		if err != nil {
			return ResolveResult{}, folderNotFoundOrInternal(err)
		}
		folderID = f.ID
	} else {
		// Every segment is a folder; walk the shared leaf->root path resolver.
		id, err := resolveFolderIDByPath(ctx, s.q, ref)
		if err != nil {
			return ResolveResult{}, folderNotFoundOrInternal(err)
		}
		folderID = id
	}

	// A caller without the read cap must not be able to distinguish an existing-but-
	// invisible folder from a nonexistent one, so a denial is reported as NotFound.
	if s.guard.RequireCap(ctx, caller, authz.FolderReadCap, authz.FolderScope(folderID)) != nil {
		return ResolveResult{}, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}

	fp, err := s.q.FolderPath(ctx, folderID)
	if err != nil {
		return ResolveResult{}, connect.NewError(connect.CodeInternal, err)
	}
	return ResolveResult{ID: folderID.String(), Path: fp}, nil
}

// DeleteFolder removes a folder only if nothing references it — child folders/assets,
// folder-scoped roles/groups homed in it, or bindings/policies scoped to it. It lists
// the blockers rather than cascading. Existence-hidden (NotFound) if the caller cannot
// read it.
func (s *Service) DeleteFolder(ctx context.Context, caller uuid.UUID, id uuid.UUID) error {
	// Existence-hide: a caller who can't read it sees NotFound; then require delete.
	if s.guard.RequireCap(ctx, caller, authz.FolderReadCap, authz.FolderScope(id)) != nil {
		return connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	if err := s.guard.RequireCap(ctx, caller, "catalog:folder:delete", authz.FolderScope(id)); err != nil {
		return err
	}

	// Count every referencing relation. Signatures differ: assets.folder_id is NOT
	// NULL (uuid.UUID); the rest are nullable (pgtype.UUID) — so call each directly.
	var blockers []string
	appendBlocker := func(n int64, label string) {
		if n > 0 {
			blockers = append(blockers, fmt.Sprintf("%d %s", n, label))
		}
	}
	nChildFolders, err := s.q.CountChildFolders(ctx, pgconv.UUID(id))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nChildFolders, "child folders")
	nAssets, err := s.q.CountAssetsInFolder(ctx, id)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nAssets, "assets")
	nRoles, err := s.q.CountRolesHomedInFolder(ctx, pgconv.UUID(id))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nRoles, "roles homed here")
	nGroups, err := s.q.CountGroupsHomedInFolder(ctx, pgconv.UUID(id))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nGroups, "groups homed here")
	nBindings, err := s.q.CountBindingsScopedToFolder(ctx, pgconv.UUID(id))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nBindings, "bindings scoped here")
	nPolicies, err := s.q.CountPoliciesScopedToFolder(ctx, pgconv.UUID(id))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	appendBlocker(nPolicies, "policies scoped here")

	if len(blockers) > 0 {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("folder not empty: %s", strings.Join(blockers, ", ")))
	}
	if err := s.q.DeleteFolder(ctx, id); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// UpdateFolderInput carries the optional rename/reparent fields for UpdateFolder. A
// nil pointer means "leave unchanged"; a non-nil ParentID of "" moves to the root.
type UpdateFolderInput struct {
	Name     *string
	ParentID *string
}

// UpdateFolder renames and/or reparents a folder. A rename rewrites the folder row
// and its catalog_names entry (sibling collision → AlreadyExists). A move guards
// against a cycle (reparenting under a descendant → FailedPrecondition), re-validates
// containment for every binding/policy in the moved subtree (FailedPrecondition if it
// would strand a folder-scoped role), then rewrites parent_id and fires authz_changed.
// A ParentId of "" moves the folder to the root. Existence-hidden.
func (s *Service) UpdateFolder(ctx context.Context, caller uuid.UUID, id uuid.UUID, in UpdateFolderInput) (FolderResult, error) {
	// Existence-hide: a caller who can't read it sees NotFound; then require update.
	if s.guard.RequireCap(ctx, caller, authz.FolderReadCap, authz.FolderScope(id)) != nil {
		return FolderResult{}, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	if err := s.guard.RequireCap(ctx, caller, "catalog:folder:update", authz.FolderScope(id)); err != nil {
		return FolderResult{}, err
	}
	cur, err := s.q.GetFolder(ctx, id)
	if err != nil {
		return FolderResult{}, folderNotFoundOrInternal(err)
	}

	newName := cur.Name
	if in.Name != nil {
		newName = strings.ToLower(*in.Name)
	}
	newParent := cur.ParentID // pgtype.UUID; NULL = root
	moving := false
	if in.ParentID != nil {
		if *in.ParentID == "" {
			if cur.ParentID.Valid { // only a change if it isn't already root
				newParent, moving = pgtype.UUID{}, true
			}
		} else {
			pid, err := uuid.Parse(*in.ParentID)
			if err != nil {
				return FolderResult{}, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid parent_id"))
			}
			if !cur.ParentID.Valid || uuid.UUID(cur.ParentID.Bytes) != pid {
				// Placing the folder under its new parent requires create there.
				if err := s.guard.RequireCap(ctx, caller, authz.FolderCreateCap, authz.FolderScope(pid)); err != nil {
					return FolderResult{}, err
				}
				newParent, moving = pgconv.UUID(pid), true
			}
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return FolderResult{}, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)

	if moving {
		// Cycle guard applies only to a real destination: the root can never lie
		// inside the moved subtree, so a root move needs no cycle check.
		if newParent.Valid {
			subList, err := q.FolderSubtreeIDs(ctx, id)
			if err != nil {
				return FolderResult{}, connect.NewError(connect.CodeInternal, err)
			}
			np := uuid.UUID(newParent.Bytes)
			for _, sid := range subList {
				if sid == np {
					return FolderResult{}, connect.NewError(connect.CodeFailedPrecondition, errors.New("cannot move a folder into its own subtree"))
				}
			}
		}
		// Re-validate containment for EVERY move, including a move to the root: a root
		// move narrows the ancestor set (drops everything above the folder), which can
		// strand a folder-scoped binding/policy in the subtree.
		if err := s.validateFolderMove(ctx, q, id, newParent); err != nil {
			return FolderResult{}, err
		}
		if err := q.UpdateFolderParent(ctx, sqlc.UpdateFolderParentParams{ID: id, ParentID: newParent}); err != nil {
			return FolderResult{}, mapWrite(err)
		}
	}
	if newName != cur.Name || moving {
		if err := q.UpdateFolderName(ctx, sqlc.UpdateFolderNameParams{ID: id, Name: newName}); err != nil {
			return FolderResult{}, mapWrite(err)
		}
		if err := q.UpdateFolderCatalogName(ctx, sqlc.UpdateFolderCatalogNameParams{FolderID: pgconv.UUID(id), ParentID: newParent, Name: newName}); err != nil {
			return FolderResult{}, mapWrite(err) // sibling collision -> AlreadyExists
		}
	}
	if moving {
		if err := q.NotifyAuthzChanged(ctx); err != nil {
			return FolderResult{}, connect.NewError(connect.CodeInternal, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return FolderResult{}, connect.NewError(connect.CodeInternal, err)
	}

	f, err := s.q.GetFolder(ctx, id)
	if err != nil {
		return FolderResult{}, connect.NewError(connect.CodeInternal, err)
	}
	res := FolderResult{Folder: f}
	if path, perr := s.q.FolderPath(ctx, f.ID); perr == nil {
		res.Path = path
	}
	return res, nil
}
