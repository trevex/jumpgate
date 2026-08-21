package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// This file implements the two "visible under a parent" queries that back the
// catalog browse (ListFolders / ListAssets). Both unify the same two axes:
//
//   - the MANAGEMENT axis: a user who holds "catalog:folder:read" /
//     "catalog:asset:read" at a scope may see the folder/asset as an
//     administrator, independent of any access grant. Management authority
//     cascades structurally down the folder tree (CapabilitiesOnScope already
//     folds in the folder ancestor chain), so we evaluate it per candidate folder.
//
//   - the ACCESS axis: a user may see an asset they can actually reach —
//     VisibleAssets(user) (active standing role OR requestable). A folder is
//     access-visible when its subtree contains such an asset (so the browse path
//     to a reachable asset is never hidden).
//
// A node is visible iff it is visible on EITHER axis (union). Deactivated users
// are handled by the underlying closures (heldCTE / globalHeldCTE / VisibleAssets
// all exclude a deactivated user), so no extra guard is needed here.

// childFolderIDs returns the ids of the folders directly under parent, ordered by
// (name, id). parent == uuid.Nil selects the tree root (parent_id IS NULL); the
// `IS NOT DISTINCT FROM` predicate treats a NULL argument as "match NULL".
func (s *sqlAuthorizer) childFolderIDs(ctx context.Context, parent uuid.UUID) ([]uuid.UUID, error) {
	var arg *uuid.UUID
	if parent != uuid.Nil {
		arg = &parent
	}
	rows, err := s.pool.Query(ctx, `
SELECT id FROM folders WHERE parent_id IS NOT DISTINCT FROM $1 ORDER BY name, id`, arg)
	if err != nil {
		return nil, fmt.Errorf("child folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// folderSubtreeIDs returns every folder id in the subtrees rooted at `roots`
// (inclusive), via a single recursive down-walk (parent_id = ancestor.id).
func (s *sqlAuthorizer) folderSubtreeIDs(ctx context.Context, roots []uuid.UUID) ([]uuid.UUID, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE sub AS (
    SELECT id FROM folders WHERE id = ANY($1::uuid[])
  UNION
    SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id
)
SELECT id FROM sub`, roots)
	if err != nil {
		return nil, fmt.Errorf("folder subtree: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// allFolderIDs returns every folder id (used for the root+cascade case, where the
// candidate set is the whole tree).
func (s *sqlAuthorizer) allFolderIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM folders`)
	if err != nil {
		return nil, fmt.Errorf("all folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// assetIDsInFolders returns the ids of assets whose folder_id is in folderIDs.
func (s *sqlAuthorizer) assetIDsInFolders(ctx context.Context, folderIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(folderIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT id FROM assets WHERE folder_id = ANY($1::uuid[])`, folderIDs)
	if err != nil {
		return nil, fmt.Errorf("assets in folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// assetFolders returns the (assetID, folderID) pairs for the given folders, so the
// caller can group assets by folder and run one management check per folder.
func (s *sqlAuthorizer) assetFolders(ctx context.Context, folderIDs []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	if len(folderIDs) == 0 {
		return map[uuid.UUID]uuid.UUID{}, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT id, folder_id FROM assets WHERE folder_id = ANY($1::uuid[])`, folderIDs)
	if err != nil {
		return nil, fmt.Errorf("asset folders: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]uuid.UUID{}
	for rows.Next() {
		var assetID, folderID uuid.UUID
		if err := rows.Scan(&assetID, &folderID); err != nil {
			return nil, fmt.Errorf("scan asset folder: %w", err)
		}
		out[assetID] = folderID
	}
	return out, rows.Err()
}

// scanUUIDs collects a single-column uuid result into a slice.
func scanUUIDs(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan uuid: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// childCandidateFolderIDs computes the folders LISTED as a browse level under
// `parent` (used by VisibleFoldersUnder): the immediate children of `parent`, or
// (with cascade) those children expanded to their full subtrees. parent ==
// uuid.Nil selects the root children (and, with cascade, the whole tree).
func (s *sqlAuthorizer) childCandidateFolderIDs(ctx context.Context, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	if parent == uuid.Nil && cascade {
		return s.allFolderIDs(ctx)
	}
	children, err := s.childFolderIDs(ctx, parent)
	if err != nil {
		return nil, err
	}
	if !cascade {
		return children, nil
	}
	return s.folderSubtreeIDs(ctx, children)
}

// assetContainerFolderIDs computes the folders whose assets are IN SCOPE for a
// browse under `parent` (used by VisibleAssetsUnder). Assets live directly in a
// folder, so the immediate level is `parent` itself; a cascade is the whole
// subtree rooted at `parent` (inclusive). parent == uuid.Nil is the root, which
// holds no assets: without cascade the set is empty, with cascade it is the whole
// tree.
func (s *sqlAuthorizer) assetContainerFolderIDs(ctx context.Context, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	if parent == uuid.Nil {
		if !cascade {
			return nil, nil
		}
		return s.allFolderIDs(ctx)
	}
	if !cascade {
		return []uuid.UUID{parent}, nil
	}
	return s.folderSubtreeIDs(ctx, []uuid.UUID{parent})
}

// accessibleAssetSet returns the set of asset ids the user can access (VisibleAssets:
// active or requestable) — the ACCESS axis, computed once per call.
func (s *sqlAuthorizer) accessibleAssetSet(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	vis, err := s.VisibleAssets(ctx, userID)
	if err != nil {
		return nil, err
	}
	set := make(map[uuid.UUID]struct{}, len(vis))
	for _, v := range vis {
		set[v.AssetID] = struct{}{}
	}
	return set, nil
}

// VisibleAssetsUnder returns the asset ids under `parent` the user may see. See the
// Authorizer interface for the visibility predicate.
//
// Management arm: an asset is manageable iff the user holds "catalog:asset:read"
// on its folder scope. If the user holds that capability GLOBALLY the arm is true
// for every candidate asset (short-circuit, one query). Otherwise it is evaluated
// once per candidate FOLDER via CapabilitiesOnScope(FolderScope(f)) — never per
// asset — and every asset in a manageable folder is manageable.
//
// Access arm: an asset is accessible iff it is in VisibleAssets(user).
func (s *sqlAuthorizer) VisibleAssetsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	candidateFolders, err := s.assetContainerFolderIDs(ctx, parent, cascade)
	if err != nil {
		return nil, err
	}
	if len(candidateFolders) == 0 {
		return nil, nil
	}
	assetFolder, err := s.assetFolders(ctx, candidateFolders)
	if err != nil {
		return nil, err
	}
	if len(assetFolder) == 0 {
		return nil, nil
	}

	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Management arm: global short-circuit, else one CapabilitiesOnScope per folder.
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	globalManage := global.Allows("catalog:asset:read")
	manageableFolder := map[uuid.UUID]bool{}
	folderManageable := func(folderID uuid.UUID) (bool, error) {
		if globalManage {
			return true, nil
		}
		if v, ok := manageableFolder[folderID]; ok {
			return v, nil
		}
		caps, err := s.CapabilitiesOnScope(ctx, userID, FolderScope(folderID))
		if err != nil {
			return false, err
		}
		v := caps.Allows("catalog:asset:read")
		manageableFolder[folderID] = v
		return v, nil
	}

	// Iterate assets in the deterministic order of assetIDsInFolders so the output
	// is stable (the handler re-sorts via the keyset query regardless).
	assetIDs, err := s.assetIDsInFolders(ctx, candidateFolders)
	if err != nil {
		return nil, err
	}
	var out []uuid.UUID
	for _, assetID := range assetIDs {
		if _, ok := accessible[assetID]; ok {
			out = append(out, assetID)
			continue
		}
		manage, err := folderManageable(assetFolder[assetID])
		if err != nil {
			return nil, err
		}
		if manage {
			out = append(out, assetID)
		}
	}
	return out, nil
}

// VisibleFoldersUnder returns the folder ids under `parent` the user may see. See
// the Authorizer interface for the visibility predicate.
//
// Management arm: a folder is manageable iff the user holds "catalog:folder:read"
// on it. A GLOBAL hold short-circuits to "all level folders" (one query).
//
// Access arm: a folder is access-visible iff its subtree (inclusive) contains an
// asset the user can access (VisibleAssets), so the browse path to a reachable
// asset is never hidden.
func (s *sqlAuthorizer) VisibleFoldersUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	levelFolders, err := s.childCandidateFolderIDs(ctx, parent, cascade)
	if err != nil {
		return nil, err
	}
	if len(levelFolders) == 0 {
		return nil, nil
	}

	// Management arm: global short-circuit.
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	if global.Allows("catalog:folder:read") {
		return levelFolders, nil
	}

	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}

	var out []uuid.UUID
	for _, folderID := range levelFolders {
		// Management arm (per folder).
		caps, err := s.CapabilitiesOnScope(ctx, userID, FolderScope(folderID))
		if err != nil {
			return nil, err
		}
		if caps.Allows("catalog:folder:read") {
			out = append(out, folderID)
			continue
		}
		// Access arm: does the subtree hold an accessible asset?
		// TODO(perf): in cascade mode this issues O(F) overlapping subtree/asset
		// queries (one folderSubtreeIDs + one assetIDsInFolders per non-manageable
		// folder). A single level-wide asset→ancestor map hoisted before the loop
		// would reduce that to two queries total.
		subtree, err := s.folderSubtreeIDs(ctx, []uuid.UUID{folderID})
		if err != nil {
			return nil, err
		}
		assetIDs, err := s.assetIDsInFolders(ctx, subtree)
		if err != nil {
			return nil, err
		}
		for _, assetID := range assetIDs {
			if _, ok := accessible[assetID]; ok {
				out = append(out, folderID)
				break
			}
		}
	}
	return out, nil
}
