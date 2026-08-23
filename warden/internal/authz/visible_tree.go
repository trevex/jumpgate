package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
//     VisibleAssets(user) (active standing role OR requestable), OR an asset they
//     are CONNECT-visible on: the full CapabilitiesOnScope(AssetScope) cascade
//     (global ∪ ancestor folders ∪ asset, `**` retained) entitles ≥1 of the asset's
//     own SSH logins, so a folder-scoped ssh:login binding surfaces its asset. A
//     folder is access-visible when its subtree contains such an asset (so the
//     browse path to a reachable asset is never hidden).
//
// A node is visible iff it is visible on EITHER axis (union). Deactivated users
// are handled by the underlying closures (heldCTE / globalHeldCTE / VisibleAssets
// all exclude a deactivated user), so no extra guard is needed here for the
// management axis. The asset-browse access axis is covered by VisibleAssets.

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

// folderSubtreeIDsRecursive returns every folder id in the subtrees rooted at
// `roots` (inclusive), via a single recursive down-walk (parent_id =
// ancestor.id). Kept as the differential-test reference implementation; hot
// paths use folderSubtreeIDs (ltree-backed) instead.
func (s *sqlAuthorizer) folderSubtreeIDsRecursive(ctx context.Context, roots []uuid.UUID) ([]uuid.UUID, error) {
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

// assetLoginsFor returns, for each asset in assetIDs, the set of SSH login names
// declared on it (ssh_asset_login.login). Assets with no logins are absent from
// the map. Batched into a single query so the connect-visibility arm never issues
// a per-asset login lookup.
func (s *sqlAuthorizer) assetLoginsFor(ctx context.Context, assetIDs []uuid.UUID) (map[uuid.UUID][]string, error) {
	if len(assetIDs) == 0 {
		return map[uuid.UUID][]string{}, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT asset_id, login FROM ssh_asset_login WHERE asset_id = ANY($1::uuid[]) ORDER BY login`, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("asset logins: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID][]string{}
	for rows.Next() {
		var (
			assetID uuid.UUID
			login   string
		)
		if err := rows.Scan(&assetID, &login); err != nil {
			return nil, fmt.Errorf("scan asset login: %w", err)
		}
		out[assetID] = append(out[assetID], login)
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

	// Connect arm (folder+global data-plane cascade): an asset not visible on the
	// access or management arm is still visible when the caller entitles ≥1 of its
	// OWN SSH logins via the full CapabilitiesOnScope(AssetScope) cascade
	// (ssh:login:<login> held globally / on an ancestor folder / on the asset). This
	// is the residual work: we only fetch logins and per-asset caps for candidates
	// that neither arm above already covered — a `**` / catalog:asset:read admin is
	// fast-pathed via folderManageable and never reaches here. `residual` collects
	// those, and we batch their login fetch into one query.
	var residual []uuid.UUID
	out := make([]uuid.UUID, 0, len(assetIDs))
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
			continue
		}
		residual = append(residual, assetID)
	}

	if len(residual) > 0 {
		loginsByAsset, err := s.assetLoginsFor(ctx, residual)
		if err != nil {
			return nil, err
		}
		for _, assetID := range residual {
			logins := loginsByAsset[assetID]
			if len(logins) == 0 {
				continue // no logins to entitle → not connect-visible
			}
			caps, err := s.CapabilitiesOnScope(ctx, userID, AssetScope(assetID))
			if err != nil {
				return nil, err
			}
			if len(caps.EntitledLogins(logins)) > 0 {
				out = append(out, assetID)
			}
		}
	}
	return out, nil
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
func (s *sqlAuthorizer) VisibleFoldersUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]VisibleFolder, error) {
	// Global management short-circuit: a global catalog:folder:read (or **) holder
	// governs and sees the whole tree.
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	if global.Allows("catalog:folder:read") {
		return s.allFoldersAtLevel(ctx, parent, cascade, true) // governed=true
	}

	// Pass 1 — anchors (bounded work; each helper already implemented).
	mgmt, err := s.mgmtScopeFolders(ctx, userID)
	if err != nil {
		return nil, err
	}
	roleHomes, err := s.visibleRoleHomeFolders(ctx, userID)
	if err != nil {
		return nil, err
	}
	groupHomes, err := s.visibleGroupHomeFolders(ctx, userID)
	if err != nil {
		return nil, err
	}
	assetHomes, err := s.visibleAssetFolders(ctx, userID)
	if err != nil {
		return nil, err
	}
	anchors := unionKeys(mgmt, roleHomes, groupHomes, assetHomes)
	if len(anchors) == 0 {
		return nil, nil
	}
	mgmtIDs := mapKeys(mgmt)

	// Pass 2 — one ltree query. Level predicate mirrors childCandidateFolderIDs:
	//   cascade=false -> direct children of parent (NULL-safe);
	//   cascade=true  -> the subtree under parent (root => whole tree).
	// A folder is visible if it is an ancestor-or-self of an anchor (path reveal)
	// OR inside a folder the user manages (cascade down). governed = the latter.
	sql, args := s.visibleFoldersQuery(parent, cascade, anchors, mgmtIDs)
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("visible folders (ltree): %w", err)
	}
	defer rows.Close()
	var out []VisibleFolder
	for rows.Next() {
		var vf VisibleFolder
		if err := rows.Scan(&vf.ID, &vf.Governed); err != nil {
			return nil, fmt.Errorf("scan visible folder: %w", err)
		}
		out = append(out, vf)
	}
	return out, rows.Err()
}

// visibleFoldersQuery builds the single-query, two-anchor-set path-reveal SELECT
// used by VisibleFoldersUnder. `anchors` are the folders whose path must be
// revealed (ancestor-or-self); `mgmtIDs` are the folders the user manages (their
// subtrees are visible AND governed). The `<LEVEL>` predicate is inlined per the
// (parent, cascade) case exactly as childCandidateFolderIDs computes the browse
// level; a nil `parent` is bound as SQL NULL via `parent_id IS NOT DISTINCT FROM`
// (matching childFolderIDs) or, for cascade, means the whole tree (no predicate).
func (s *sqlAuthorizer) visibleFoldersQuery(parent uuid.UUID, cascade bool, anchors, mgmtIDs []uuid.UUID) (string, []any) {
	// $1 anchors, $2 mgmtIDs; $3 (when present) is the parent binding.
	args := []any{anchors, mgmtIDs}
	var level string
	switch {
	case cascade && parent == uuid.Nil:
		// Whole tree: every folder is at the level.
		level = "TRUE"
	case cascade:
		// Subtree under parent (inclusive).
		args = append(args, parent)
		level = "f.path_ids <@ (SELECT path_ids FROM folders WHERE id = $3)"
	case parent == uuid.Nil:
		// Direct children of the root (parent_id IS NULL), bound NULL-safe.
		args = append(args, (*uuid.UUID)(nil))
		level = "f.parent_id IS NOT DISTINCT FROM $3"
	default:
		// Direct children of parent.
		args = append(args, parent)
		level = "f.parent_id IS NOT DISTINCT FROM $3"
	}
	sql := `
WITH anchor_paths AS (SELECT path_ids FROM folders WHERE id = ANY($1::uuid[])),
     mgmt_paths   AS (SELECT path_ids FROM folders WHERE id = ANY($2::uuid[]))
SELECT f.id,
       EXISTS (SELECT 1 FROM mgmt_paths m WHERE f.path_ids <@ m.path_ids) AS governed
FROM folders f
WHERE ` + level + `
  AND ( EXISTS (SELECT 1 FROM anchor_paths a WHERE f.path_ids @> a.path_ids)
     OR EXISTS (SELECT 1 FROM mgmt_paths  m WHERE f.path_ids <@ m.path_ids) )
ORDER BY f.name, f.id`
	return sql, args
}

// allFoldersAtLevel returns every folder at the browse level under `parent`
// (reusing childCandidateFolderIDs), each with the given `governed` flag. It backs
// the global-management short-circuit in VisibleFoldersUnder, where the caller sees
// (and governs) the whole tree without per-folder anchor work.
func (s *sqlAuthorizer) allFoldersAtLevel(ctx context.Context, parent uuid.UUID, cascade, governed bool) ([]VisibleFolder, error) {
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

// unionKeys collects the union of the keys of the given sets into a slice.
func unionKeys(maps ...map[uuid.UUID]struct{}) []uuid.UUID {
	seen := map[uuid.UUID]struct{}{}
	var out []uuid.UUID
	for _, m := range maps {
		for k := range m {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

// mapKeys returns the keys of a set as a slice (order-independent).
func mapKeys(m map[uuid.UUID]struct{}) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── Role / group visibility ────────────────────────────────────────────────
//
// VisibleRolesUnder and VisibleGroupsUnder generalize the union-visibility model
// (see the file header) to the two node kinds that are homed in the folder tree
// via a NULLABLE folder_id (NULL = global/root). Both unify:
//
//   - the MANAGEMENT axis: a user holding the read capability
//     ("access:role:read" / "identity:group:read") at the node's home-folder
//     scope sees the node as an administrator. A GLOBAL hold short-circuits to
//     "manageable everywhere" (one query). A folder-less (global) node has no
//     folder scope, so it is manageable ONLY via that global cap.
//
//   - the ACCESS axis: a role is access-visible when the user HOLDS it (standing
//     closure) or it is REQUESTABLE to them; a group is access-visible when the
//     user is a (transitive) MEMBER.
//
// Deactivated users are excluded by the underlying closures: heldCTE and
// visibleRequestable both carry the `deactivated_at IS NULL` EXISTS guard, and
// memberGroupIDs carries an explicit EXISTS guard in its final SELECT (see
// memberGroupIDs below). No extra guard is needed at the VisibleRolesUnder /
// VisibleGroupsUnder call site.

// nodeFolder is one folder-homed node: Folder is nil for a global (folder-less)
// node (folder_id IS NULL).
type nodeFolder struct {
	ID     uuid.UUID
	Folder *uuid.UUID
}

// nodesHomedUnder returns the (id, home-folder) rows of `table` homed under
// `parent`. `table` is a TRUSTED literal — callers pass only "roles" or "groups";
// it is interpolated into the query and must never be attacker-controlled.
//
// Four cases mirror the folder-candidate logic:
//   - (uuid.Nil, !cascade): folder-less nodes only (folder_id IS NULL).
//   - (uuid.Nil, cascade):  every node.
//   - (parent,   !cascade): nodes homed directly in `parent`.
//   - (parent,   cascade):  nodes homed anywhere in the subtree rooted at `parent`.
func (s *sqlAuthorizer) nodesHomedUnder(ctx context.Context, table string, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	var (
		query string
		args  []any
	)
	switch {
	case parent == uuid.Nil && !cascade:
		query = "SELECT id, folder_id FROM " + table + " WHERE folder_id IS NULL"
	case parent == uuid.Nil && cascade:
		query = "SELECT id, folder_id FROM " + table
	case !cascade:
		query = "SELECT id, folder_id FROM " + table + " WHERE folder_id = $1"
		args = []any{parent}
	default: // parent set, cascade
		subtree, err := s.folderSubtreeIDs(ctx, []uuid.UUID{parent})
		if err != nil {
			return nil, err
		}
		if len(subtree) == 0 {
			return nil, nil
		}
		query = "SELECT id, folder_id FROM " + table + " WHERE folder_id = ANY($1::uuid[])"
		args = []any{subtree}
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("nodes homed under (%s): %w", table, err)
	}
	defer rows.Close()
	var out []nodeFolder
	for rows.Next() {
		var (
			id     uuid.UUID
			folder *uuid.UUID
		)
		if err := rows.Scan(&id, &folder); err != nil {
			return nil, fmt.Errorf("scan node folder (%s): %w", table, err)
		}
		out = append(out, nodeFolder{ID: id, Folder: folder})
	}
	return out, rows.Err()
}

// heldRoleIDs returns the set of role ids the user holds (standing bindings +
// active grants, closed over the role_grants rewrite graph) — one arm of the
// role ACCESS axis. Object dimension is dropped: a role is "held" if held on ANY
// object.
func (s *sqlAuthorizer) heldRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT role_id FROM held`, userID)
	if err != nil {
		return nil, fmt.Errorf("held role ids: %w", err)
	}
	defer rows.Close()
	return scanUUIDSet(rows)
}

// requestableRoleIDs returns the set of role ids requestable to the user across
// all assets — the other arm of the role ACCESS axis.
func (s *sqlAuthorizer) requestableRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	reqs, err := s.visibleRequestable(ctx, userID)
	if err != nil {
		return nil, err
	}
	set := make(map[uuid.UUID]struct{}, len(reqs))
	for _, r := range reqs {
		set[r.RoleID] = struct{}{}
	}
	return set, nil
}

// IsMember reports whether the user is a (transitive) member of groupID. Returns
// false for deactivated users. One targeted query, never full closure.
func (s *sqlAuthorizer) IsMember(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT EXISTS(
    SELECT 1 FROM user_groups WHERE group_id = $2
) AND EXISTS(SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`, userID, groupID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("is member: %w", err)
	}
	return ok, nil
}

// memberGroupIDs returns the set of group ids the user is a (transitive) member
// of — the group ACCESS axis. The user_groups CTE is copied VERBATIM from heldCTE
// / globalHeldCTE (direct membership base + recursive nested-group arm).
//
// The final SELECT carries the deactivation guard via an EXISTS sub-select on
// users.deactivated_at IS NULL (matching the predicate in heldCTE and
// globalHeldCTE). A deactivated user therefore yields an empty set.
func (s *sqlAuthorizer) memberGroupIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT group_id FROM user_groups
WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`, userID)
	if err != nil {
		return nil, fmt.Errorf("member group ids: %w", err)
	}
	defer rows.Close()
	return scanUUIDSet(rows)
}

// scanUUIDSet collects a single-column uuid result into a set.
func scanUUIDSet(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) (map[uuid.UUID]struct{}, error) {
	out := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan uuid: %w", err)
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// manageFn tests whether the user may manage a node given its home folder.
// folderPtr is nil for a folder-less (global) node — manageable ONLY via the
// global cap, since a nil home has no folder scope to fold an ancestor chain from.
type manageFn func(folderPtr *uuid.UUID) (bool, error)

// folderManageableFunc builds a memoized predicate "may the user manage a node
// homed at this folder?" with the global short-circuit: if the user holds `cap`
// GLOBALLY the predicate is always true (one query, no per-folder work);
// otherwise it evaluates CapabilitiesOnScope(FolderScope(folder)) once per folder
// (which already folds global ∪ the folder ancestor chain). A folder-less node
// (nil folder) is manageable iff the global cap holds — never via a folder scope.
func (s *sqlAuthorizer) folderManageableFunc(ctx context.Context, userID uuid.UUID, capability string) (manageFn, error) {
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	globalManage := global.Allows(capability)
	memo := map[uuid.UUID]bool{}
	return func(folderPtr *uuid.UUID) (bool, error) {
		if globalManage {
			return true, nil
		}
		if folderPtr == nil {
			// Folder-less (global) node: no folder scope, so only the global cap
			// (already checked above and false here) could ever make it manageable.
			return false, nil
		}
		if v, ok := memo[*folderPtr]; ok {
			return v, nil
		}
		caps, err := s.CapabilitiesOnScope(ctx, userID, FolderScope(*folderPtr))
		if err != nil {
			return false, err
		}
		v := caps.Allows(capability)
		memo[*folderPtr] = v
		return v, nil
	}, nil
}

// visibleRolesHomed returns the roles under `parent` the user may see, each with
// its home folder, applying the full role-visibility predicate (held ∪
// requestable ∪ manageable-via access:role:read). It is the single source of
// truth for that predicate: VisibleRolesUnder maps it to ids, and the folder-anchor
// helper reads its home folders — neither re-implements the predicate.
func (s *sqlAuthorizer) visibleRolesHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	nodes, err := s.nodesHomedUnder(ctx, "roles", parent, cascade)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}

	// Access axis: held ∪ requestable, computed once.
	held, err := s.heldRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	requestable, err := s.requestableRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}

	manageable, err := s.folderManageableFunc(ctx, userID, "access:role:read")
	if err != nil {
		return nil, err
	}

	var out []nodeFolder
	for _, n := range nodes {
		if _, ok := held[n.ID]; ok {
			out = append(out, n)
			continue
		}
		if _, ok := requestable[n.ID]; ok {
			out = append(out, n)
			continue
		}
		// Management axis (folder-less nodes handled inside manageable: nil folder
		// ⇒ manageable only via the global cap, never a synthesized folder scope).
		ok, err := manageable(n.Folder)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// VisibleRolesUnder returns the role ids under `parent` the user may see. See the
// Authorizer interface for the visibility predicate.
func (s *sqlAuthorizer) VisibleRolesUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := s.visibleRolesHomed(ctx, userID, parent, cascade)
	if err != nil {
		return nil, err
	}
	return nodeIDs(nodes), nil
}

// visibleGroupsHomed returns the groups under `parent` the user may see, each with
// its home folder, applying the full group-visibility predicate (transitive
// membership ∪ manageable-via identity:group:read). Single source of truth for the
// predicate: VisibleGroupsUnder maps it to ids and the folder-anchor helper reads
// its home folders.
func (s *sqlAuthorizer) visibleGroupsHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	nodes, err := s.nodesHomedUnder(ctx, "groups", parent, cascade)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}

	// Access axis: transitive membership, computed once.
	member, err := s.memberGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}

	manageable, err := s.folderManageableFunc(ctx, userID, "identity:group:read")
	if err != nil {
		return nil, err
	}

	var out []nodeFolder
	for _, n := range nodes {
		if _, ok := member[n.ID]; ok {
			out = append(out, n)
			continue
		}
		ok, err := manageable(n.Folder)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// VisibleGroupsUnder returns the group ids under `parent` the user may see. See
// the Authorizer interface for the visibility predicate.
func (s *sqlAuthorizer) VisibleGroupsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := s.visibleGroupsHomed(ctx, userID, parent, cascade)
	if err != nil {
		return nil, err
	}
	return nodeIDs(nodes), nil
}

// nodeIDs projects the ids out of a []nodeFolder (preserving order).
func nodeIDs(nodes []nodeFolder) []uuid.UUID {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]uuid.UUID, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// nodeHomeFolders collects the non-nil home folders of the given nodes into a set.
// Folder-less (global) nodes contribute no anchor.
func nodeHomeFolders(nodes []nodeFolder) map[uuid.UUID]struct{} {
	out := map[uuid.UUID]struct{}{}
	for _, n := range nodes {
		if n.Folder != nil {
			out[*n.Folder] = struct{}{}
		}
	}
	return out
}

// visibleRoleHomeFolders returns the set of home folders of every role visible to
// the user (whole-tree cascade). These folders anchor path-reveal so the browse
// path down to a visible role is never hidden.
func (s *sqlAuthorizer) visibleRoleHomeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	nodes, err := s.visibleRolesHomed(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	return nodeHomeFolders(nodes), nil
}

// visibleGroupHomeFolders returns the set of home folders of every group visible to
// the user (whole-tree cascade). These folders anchor path-reveal so the browse
// path down to a visible group is never hidden.
func (s *sqlAuthorizer) visibleGroupHomeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	nodes, err := s.visibleGroupsHomed(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	return nodeHomeFolders(nodes), nil
}

// ── Folder anchors (catalog path-reveal) ───────────────────────────────────
//
// A folder is an "anchor" when the user has a relationship to a folder-homed node
// at or under it, so the browse PATH to that node must be revealed. The three
// helpers below compute the three anchor-source SETS of folder ids; a caller
// unions them (and does the ltree path expansion) elsewhere.

// isManagementCap reports whether a capability pattern grants management (as
// opposed to pure connect). Management = anything under catalog:/access:/identity:
// or the broad `**` wildcard (the admin cap, which matches every capability at any
// depth). A bare ssh:* is connect and does NOT anchor a folder.
//
// A bare `*` is matched here defensively but is inert in practice: `*` matches
// exactly ONE segment and never crosses a `:` (docs/capabilities.md), so it never
// matches a concrete management capability like `catalog:folder:read`, and it is
// rejected as a stored pattern at CreateRole. `**` is the real broad wildcard.
func isManagementCap(pat string) bool {
	if pat == "**" || pat == "*" {
		return true
	}
	return strings.HasPrefix(pat, "catalog:") ||
		strings.HasPrefix(pat, "access:") ||
		strings.HasPrefix(pat, "identity:")
}

// mgmtScopeFolders returns the folder scopes at which the user holds a role that
// grants a management capability (folder/asset/role/group admin). Bounded by the
// user's held folder-bindings (the held closure, object_kind='folder'); glob
// classification is done in Go over that small set. These folders are both a
// path-reveal anchor source and the set whose subtrees VisibleFoldersUnder marks
// `governed`: a folder is governed iff it is at/under one of these scopes.
//
// roles.capabilities is a jsonb pattern array, so — exactly as scanCapabilities /
// capsOnFolders do — it is scanned as raw bytes and json-unmarshaled into the
// Capabilities ([]string) set (it has no pgx codec for a direct scan).
func (s *sqlAuthorizer) mgmtScopeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT h.object_id, r.capabilities
FROM held h JOIN roles r ON r.id = h.role_id
WHERE h.object_kind = 'folder'`, userID)
	if err != nil {
		return nil, fmt.Errorf("mgmt scope folders: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			fid uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&fid, &raw); err != nil {
			return nil, fmt.Errorf("scan mgmt scope: %w", err)
		}
		var patterns Capabilities
		if err := json.Unmarshal(raw, &patterns); err != nil {
			return nil, fmt.Errorf("mgmt scope unmarshal: %w", err)
		}
		for _, c := range patterns {
			if isManagementCap(c) {
				out[fid] = struct{}{}
				break
			}
		}
	}
	return out, rows.Err()
}

// visibleAssetFolders returns the home folders of every asset visible to the user
// (the full VisibleAssetsUnder union: access ∪ management ∪ connect, whole-tree
// cascade). These folders anchor the path down to a reachable asset.
func (s *sqlAuthorizer) visibleAssetFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	assetIDs, err := s.VisibleAssetsUnder(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	if len(assetIDs) == 0 {
		return map[uuid.UUID]struct{}{}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT folder_id FROM assets WHERE id = ANY($1::uuid[])`, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("visible asset folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDSet(rows)
}
