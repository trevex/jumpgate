package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// childFolderIDs returns the ids of the folders directly under parent, ordered by
// (name, id). parent == uuid.Nil selects the tree root (parent_id IS NULL); the
// `IS NOT DISTINCT FROM` predicate treats a NULL argument as "match NULL".
func (s *Authorizer) childFolderIDs(ctx context.Context, parent uuid.UUID) ([]uuid.UUID, error) {
	ids, err := s.queries().ChildFolderIDs(ctx, nullableUUIDArg(parent))
	if err != nil {
		return nil, fmt.Errorf("child folders: %w", err)
	}
	return ids, nil
}

// allFolderIDs returns every folder id (used for the root+cascade case, where the
// candidate set is the whole tree).
func (s *Authorizer) allFolderIDs(ctx context.Context) ([]uuid.UUID, error) {
	ids, err := s.queries().AllFolderIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("all folders: %w", err)
	}
	return ids, nil
}

// childCandidateFolderIDs computes the folders LISTED as a browse level under
// `parent` (used by VisibleFoldersUnder): the immediate children of `parent`, or
// (with cascade) those children expanded to their full subtrees. parent ==
// uuid.Nil selects the root children (and, with cascade, the whole tree).
func (s *Authorizer) childCandidateFolderIDs(ctx context.Context, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
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

// VisibleFoldersUnder returns the folders under `parent` the user may see, each
// with a `Governed` flag. See the Authorizer interface for the visibility model.
//
// The predicate is PATH-REVEAL. A folder is visible iff it is an ancestor-or-self
// of an ANCHOR (reveal the browse path to anything the user can see/administer) OR
// it is inside a folder the user manages (cascade down). `Governed` is the latter:
// the user holds a management cap at/under the folder — a revealed ancestor is
// visible but NOT governed (no capability is conferred on it).
//
// Anchors = the union of four bounded helper sets (already implemented):
//   - mgmtScopeFolders:        folders where the user holds a management cap;
//   - visibleRoleHomeFolders:  home folders of roles visible to the user;
//   - visibleGroupHomeFolders: home folders of groups visible to the user;
//   - visibleAssetFolders:     folders of assets visible to the user (access ∪
//     management ∪ connect).
//
// A user with a GLOBAL catalog:folder:read (or `**`) governs and sees the whole
// tree; that case short-circuits to every folder at the level with governed=true.
func (s *Authorizer) VisibleFoldersUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]VisibleFolder, error) {
	// Global management short-circuit: a global catalog:folder:read (or **) holder
	// governs and sees the whole tree.
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	if global.Allows("catalog:folder:read") {
		return s.allFoldersAtLevel(ctx, parent, cascade, true) // governed=true
	}

	// Anchors (path-reveal sources) + the governed (managed) folder set, computed
	// with the shared closures evaluated once each (folderAnchors).
	anchors, mgmtIDs, err := s.folderAnchors(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(anchors) == 0 {
		return nil, nil
	}

	// One ltree query. Level predicate mirrors childCandidateFolderIDs:
	//   cascade=false -> direct children of parent (NULL-safe);
	//   cascade=true  -> the subtree under parent (root => whole tree).
	// A folder is visible if it is an ancestor-or-self of an anchor (path reveal)
	// OR inside a folder the user manages (cascade down). governed = the latter.
	rows, err := s.queries().VisibleFoldersUnder(ctx, sqlc.VisibleFoldersUnderParams{
		Cascade: cascade,
		Parent:  nullableUUIDArg(parent),
		Anchors: anchors,
		MgmtIds: mgmtIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("visible folders (ltree): %w", err)
	}
	out := make([]VisibleFolder, 0, len(rows))
	for _, r := range rows {
		out = append(out, VisibleFolder{ID: r.ID, Governed: r.Governed})
	}
	return out, nil
}

// FolderPathVisible reports whether `folderID` is visible to the user under the
// same path-reveal model as VisibleFoldersUnder: the folder is an ancestor-or-self
// of an anchor (on the path to something the user can see/administer) OR inside a
// folder the user manages. GetFolderAccess uses it to decide existence for a folder
// the user holds no direct capability on — so a delegate can open the breadcrumb
// ancestors above the subtree they govern. A global catalog:folder:read / ** holder
// sees every folder that exists.
func (s *Authorizer) FolderPathVisible(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return false, err
	}
	if global.Allows("catalog:folder:read") {
		exists, err := s.queries().FolderExists(ctx, folderID)
		if err != nil {
			return false, fmt.Errorf("folder exists: %w", err)
		}
		return exists, nil
	}

	// Anchors (path-reveal sources) + the governed (managed) folder set, computed
	// with the shared closures evaluated once each (folderAnchors). The same anchor
	// logic backs VisibleFoldersUnder, so the two path-reveal predicates cannot drift.
	anchors, mgmtIDs, err := s.folderAnchors(ctx, userID)
	if err != nil {
		return false, err
	}
	if len(anchors) == 0 {
		return false, nil
	}

	// Visible iff folderID is an ancestor-or-self of an anchor (path reveal) OR
	// inside a folder the user manages (cascade down) — mirrors VisibleFoldersUnder.
	vis, err := s.queries().FolderPathVisible(ctx, sqlc.FolderPathVisibleParams{
		FolderID: uuidArg(folderID),
		Anchors:  anchors,
		MgmtIds:  mgmtIDs,
	})
	if err != nil {
		return false, fmt.Errorf("folder path visible: %w", err)
	}
	return vis.Bool, nil
}

// allFoldersAtLevel returns every folder at the browse level under `parent`
// (reusing childCandidateFolderIDs), each with the given `governed` flag. It backs
// the global-management short-circuit in VisibleFoldersUnder, where the caller sees
// (and governs) the whole tree without per-folder anchor work.
func (s *Authorizer) allFoldersAtLevel(ctx context.Context, parent uuid.UUID, cascade, governed bool) ([]VisibleFolder, error) {
	ids, err := s.childCandidateFolderIDs(ctx, parent, cascade)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([]VisibleFolder, 0, len(ids))
	for _, id := range ids {
		out = append(out, VisibleFolder{ID: id, Governed: governed})
	}
	return out, nil
}

// FolderIDsOf projects the ids out of a []VisibleFolder (preserving order), for
// callers/tests that only need the visible id set.
func FolderIDsOf(v []VisibleFolder) []uuid.UUID {
	if len(v) == 0 {
		return nil
	}
	out := make([]uuid.UUID, 0, len(v))
	for _, f := range v {
		out = append(out, f.ID)
	}
	return out
}
