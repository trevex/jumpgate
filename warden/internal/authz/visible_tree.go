package authz

import (
	"context"
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
//     cascades structurally down the folder tree; both queries evaluate it
//     set-based (the shared mgmtCascadeCTEs fragment: a global-cap arm ∪ an
//     ltree <@ folder-cascade arm), never per-candidate.
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
// SET-BASED: the ACCESS set (VisibleAssets = held asset-objects ∪ requestable) is
// two small constant closure queries collapsed into a uuid[] param; the candidate
// selection, management cascade, and connect cascade are ONE query off
// heldPlusGlobalHeldPrefix. Total is a small constant — no per-folder and no
// per-residual-asset CapabilitiesOnScope loop.
//
// An asset (whose folder is in scope under `parent`) is visible iff ANY of:
//
//   - ACCESS:     a.id ∈ VisibleAssets(user) (a.id = ANY($5)); OR
//   - MANAGEMENT: the user holds "catalog:asset:read" on the asset's folder scope —
//     GLOBAL (global_mgmt.ok) covers every asset, else the asset's folder is a
//     descendant-or-self of a folder where the cap is held (mgmt_anchor_folders,
//     the shared mgmtCascadeCTEs fragment with the asset's NOT-NULL folder as the
//     node folder); OR
//   - CONNECT:    the asset declares ≥1 SSH login L (ssh_asset_login) that the user
//     entitles over the FULL asset-scope cascade — a role in global_held, held on
//     the asset object, or held on an ancestor-or-self folder of the asset's folder
//     carries a capability matching ssh:login:L. This reproduces
//     EntitledLogins on the RAW CapabilitiesOnScope(AssetScope) result: `**`
//     normalizes to (*,*,*) and the column-match makes it match ssh:login:L, so
//     `**` IS RETAINED here (no ConnectCapabilities literal-`**` carve-out).
func (s *sqlAuthorizer) VisibleAssetsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	// root + no-cascade holds no assets — short-circuit (also makes the level
	// predicate below never need a FALSE arm).
	if parent == uuid.Nil && !cascade {
		return nil, nil
	}

	// ACCESS set: VisibleAssets (held asset-objects ∪ requestable), one small
	// constant closure pair, collapsed into a uuid[] param ($5).
	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := make([]uuid.UUID, 0, len(accessible))
	for id := range accessible {
		accessIDs = append(accessIDs, id)
	}

	// $1 user (bound by the closure prefix); $2/$3/$4 the catalog:asset:read request
	// columns (the mgmtCascadeCTEs fragment); $5 the access-id set. The container
	// level predicate appends its parent bind from $6.
	reqScope, reqAction, reqQual := NormalizeCap("catalog:asset:read")
	args := []any{userID, reqScope, reqAction, reqQual, accessIDs}
	level := "TRUE"
	if parent != uuid.Nil {
		if cascade {
			// Asset's folder is a descendant-or-self of parent (whole subtree).
			args = append(args, parent)
			level = "a.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = $6))"
		} else {
			// Asset directly in parent.
			args = append(args, parent)
			level = "a.folder_id = $6"
		}
	}

	query := heldPlusGlobalHeldPrefix + mgmtCascadeCTEs + `
SELECT a.id
FROM assets a
WHERE (` + level + `)
  AND (
        -- ACCESS axis: pre-computed held asset-objects ∪ requestable.
        a.id = ANY($5::uuid[])
        -- MANAGEMENT axis, global arm: catalog:asset:read held globally.
     OR (SELECT ok FROM global_mgmt)
        -- MANAGEMENT axis, folder-cascade arm: the asset's folder is at/under a
        -- folder where the user holds catalog:asset:read.
     OR EXISTS (
            SELECT 1 FROM mgmt_anchor_folders m
            JOIN folders mf ON mf.id = m.folder_id
            JOIN folders nf ON nf.id = a.folder_id
            WHERE nf.path_ids <@ mf.path_ids
        )
        -- CONNECT axis: the asset declares an SSH login the user entitles over the
        -- FULL asset-scope cascade (global_held ∪ held-on-asset ∪ held-on-ancestor
        -- folders). A ** cap normalizes to (*,*,*) and matches ssh:login:L via the
        -- column-match, so it is retained — matching EntitledLogins on raw
        -- CapabilitiesOnScope. Shared with anchorHomeFolders via connectArmExists.
     ` + connectArmExists + `
      )
ORDER BY a.id`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("visible assets under: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
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

// FolderPathVisible reports whether `folderID` is visible to the user under the
// same path-reveal model as VisibleFoldersUnder: the folder is an ancestor-or-self
// of an anchor (on the path to something the user can see/administer) OR inside a
// folder the user manages. GetFolderAccess uses it to decide existence for a folder
// the user holds no direct capability on — so a delegate can open the breadcrumb
// ancestors above the subtree they govern. A global catalog:folder:read / ** holder
// sees every folder that exists.
func (s *sqlAuthorizer) FolderPathVisible(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return false, err
	}
	if global.Allows("catalog:folder:read") {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM folders WHERE id = $1)`, folderID).Scan(&exists); err != nil {
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
	// inside a folder the user manages (cascade down) — mirrors visibleFoldersQuery.
	var vis bool
	err = s.pool.QueryRow(ctx, `
WITH f  AS (SELECT path_ids FROM folders WHERE id = $1),
     ap AS (SELECT path_ids FROM folders WHERE id = ANY($2::uuid[])),
     mp AS (SELECT path_ids FROM folders WHERE id = ANY($3::uuid[]))
SELECT EXISTS (SELECT 1 FROM f, ap WHERE f.path_ids @> ap.path_ids)
    OR EXISTS (SELECT 1 FROM f, mp WHERE f.path_ids <@ mp.path_ids)`,
		folderID, anchors, mgmtIDs).Scan(&vis)
	if err != nil {
		return false, fmt.Errorf("folder path visible: %w", err)
	}
	return vis, nil
}

// heldRolesAndAssets scans the grant-augmented held closure ONCE and projects both
// arms of the ACCESS axis it carries: the set of role ids the user holds (object
// dimension dropped — held on ANY object) and the set of asset ids the user holds a
// role on directly (object_kind='asset'). Folding both projections into a single
// `held` scan avoids the two separate closure round-trips (heldRoleIDs + the
// VisibleAssets active tier) the legacy anchor path issued.
func (s *sqlAuthorizer) heldRolesAndAssets(ctx context.Context, userID uuid.UUID) (roles, assets map[uuid.UUID]struct{}, err error) {
	rows, err := s.pool.Query(ctx, heldCTE+`
SELECT DISTINCT object_kind, object_id, role_id FROM held`, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("held roles and assets: %w", err)
	}
	defer rows.Close()
	roles = map[uuid.UUID]struct{}{}
	assets = map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			kind     string
			objectID uuid.UUID
			roleID   uuid.UUID
		)
		if err := rows.Scan(&kind, &objectID, &roleID); err != nil {
			return nil, nil, fmt.Errorf("scan held row: %w", err)
		}
		roles[roleID] = struct{}{}
		if kind == "asset" {
			assets[objectID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return roles, assets, nil
}

// folderAnchors computes, in a small constant number of round-trips, the two folder
// sets that drive the catalog path-reveal (VisibleFoldersUnder / FolderPathVisible):
//
//   - anchors: the union of the four anchor sources (management-scope folders ∪ home
//     folders of visible roles ∪ home folders of visible groups ∪ folders of visible
//     assets) — the folders whose browse PATH must be revealed (ancestor-or-self).
//   - mgmtIDs: the folders the user MANAGES (holds a management cap at) — the set
//     whose subtrees VisibleFoldersUnder marks `governed`. mgmtIDs ⊆ anchors.
//
// The redundant closure work the legacy orchestration incurred (visibleRequestable
// re-run for roles AND assets; held/member recomputed across helpers) is eliminated:
// each shared closure is evaluated ONCE here (held roles+assets in one scan,
// visibleRequestable once for both requestable-role and requestable-asset arms,
// member groups once), and the role/group/asset home-folder anchors + connect-arm
// asset folders are resolved by ONE combined set-based query. The management-cap
// classification for the governed set (a) stays in Go over mgmtScopeFolders' single
// held-folder-rows query — its isManagementCap glob predicate (which admits a bare
// `*`/`**` but NOT a scope='*' connect pattern like `*:connect`) is subtler than a
// naive SQL scope predicate, so it is kept where CapMatch-equivalence is not at risk.
//
// Round-trips (non-admin): heldRolesAndAssets (1) + visibleRequestable (1) +
// memberGroupIDs (1) + mgmtScopeFolders (1) + the combined anchor query (1) = 5.
func (s *sqlAuthorizer) folderAnchors(ctx context.Context, userID uuid.UUID) (anchors, mgmtIDs []uuid.UUID, err error) {
	// ── Shared ACCESS closures, each evaluated once ──────────────────────────
	// held: role ids (any object) + asset ids held directly — one closure scan.
	heldRoles, heldAssets, err := s.heldRolesAndAssets(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	// requestable: (asset, role) pairs across all assets — one closure. Feeds BOTH
	// the requestable-role arm (role home anchors) and the requestable-asset arm
	// (asset home anchors), so it is not re-run per kind as the legacy path did.
	req, err := s.visibleRequestable(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	// member: transitive group membership — one closure.
	member, err := s.memberGroupIDs(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	// Role ACCESS set = held ∪ requestable roles; Asset ACCESS set = held ∪
	// requestable assets (VisibleAssets = the active tier ∪ the requestable tier).
	roleAccess := make(map[uuid.UUID]struct{}, len(heldRoles)+len(req))
	for id := range heldRoles {
		roleAccess[id] = struct{}{}
	}
	assetAccess := make(map[uuid.UUID]struct{}, len(heldAssets)+len(req))
	for id := range heldAssets {
		assetAccess[id] = struct{}{}
	}
	for _, ra := range req {
		roleAccess[ra.RoleID] = struct{}{}
		assetAccess[ra.AssetID] = struct{}{}
	}

	// ── Governed set (a): management-scope folders, isManagementCap in Go ─────
	mgmt, err := s.mgmtScopeFolders(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	mgmtIDs = mapKeys(mgmt)

	// ── Combined anchor query: role/group/asset home-folder anchors in ONE go ──
	// Anchor sources (b)+(c)+(d): the home folders of visible roles/groups and the
	// folders of visible assets, where visibility on each kind is (ACCESS set passed
	// as a uuid[] param) ∪ (MANAGEMENT via the kind's read cap, folded set-based over
	// the shared held/global_held closures) — and, for assets, ∪ (CONNECT via an
	// ssh:login the user entitles over the full asset-scope cascade). The mgmt read
	// caps are 3-segment concrete (access:role:read / identity:group:read /
	// catalog:asset:read), so their columns are literals; the three-column glob
	// predicate ((col = literal OR col = '*')) is the same one proven ≡ Go CapMatch by
	// TestSQLCapMatchMatchesGo.
	//
	// $1 user (bound by the closure prefix); $2 role-access ids; $3 group-access ids;
	// $4 asset-access ids.
	anchorFolders, err := s.anchorHomeFolders(ctx, userID, mapKeys(roleAccess), mapKeys(member), mapKeys(assetAccess))
	if err != nil {
		return nil, nil, err
	}

	// anchors = mgmt (a) ∪ role/group/asset home folders (b+c+d).
	seen := map[uuid.UUID]struct{}{}
	for id := range mgmt {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			anchors = append(anchors, id)
		}
	}
	for _, id := range anchorFolders {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			anchors = append(anchors, id)
		}
	}
	return anchors, mgmtIDs, nil
}

// anchorHomeFolders resolves, in ONE set-based query, the union of the three
// folder-id anchor sources that hang off folder-homed nodes: the home folders of
// roles/groups visible to the user and the folders of assets visible to the user.
// Visibility per kind is (the pre-computed ACCESS id set, passed as a uuid[]) ∪
// (MANAGEMENT via the kind's read cap over the shared held/global_held closures) —
// plus, for assets, the CONNECT arm (an ssh:login the user entitles over the full
// asset-scope cascade). It reuses heldPlusGlobalHeldPrefix (user_groups + held +
// global_held) so held/global_held cannot drift from Check / CapabilitiesOnScope;
// deactivated users are excluded by those closures and by the ACCESS closures that
// produced the id params.
//
//   - $1 user (bound by the closure prefix);
//   - $2 role-access ids; $3 group-access ids; $4 asset-access ids.
func (s *sqlAuthorizer) anchorHomeFolders(ctx context.Context, userID uuid.UUID, roleAccess, groupAccess, assetAccess []uuid.UUID) ([]uuid.UUID, error) {
	query := heldPlusGlobalHeldPrefix + `,
-- held FOLDER objects carrying their capability columns (the mgmt-cascade anchor
-- source, generalized to any cap via the carried columns). Management cascades DOWN
-- from a folder F where a cap is held to every folder at/under F (ltree <@).
held_folder_caps(folder_id, scope, action, qualifier) AS (
    SELECT h.object_id, rc.scope, rc.action, rc.qualifier
    FROM held h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
),
-- capabilities held GLOBALLY (the mgmt short-circuit arm; covers every folder).
global_caps(scope, action, qualifier) AS (
    SELECT rc.scope, rc.action, rc.qualifier
    FROM global_held gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
)
-- (b) role home folders: role visible via ACCESS (held ∪ requestable) OR MANAGEMENT
-- (access:role:read on the home-folder scope). Folder-less (NULL home) roles never
-- anchor a folder and are excluded by the NOT NULL join to folders.
SELECT DISTINCT r.folder_id AS folder_id
FROM roles r
JOIN folders nf ON nf.id = r.folder_id
WHERE r.id = ANY($2::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'access' OR c.scope = '*')
                AND (c.action = 'role' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR EXISTS (SELECT 1 FROM held_folder_caps hf JOIN folders mf ON mf.id = hf.folder_id
              WHERE nf.path_ids <@ mf.path_ids
                AND (hf.scope = 'access' OR hf.scope = '*')
                AND (hf.action = 'role' OR hf.action = '*')
                AND (hf.qualifier = 'read' OR hf.qualifier = '*'))
UNION
-- (c) group home folders: group visible via ACCESS (transitive membership) OR
-- MANAGEMENT (identity:group:read on the home-folder scope).
SELECT DISTINCT g.folder_id AS folder_id
FROM groups g
JOIN folders nf ON nf.id = g.folder_id
WHERE g.id = ANY($3::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'identity' OR c.scope = '*')
                AND (c.action = 'group' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR EXISTS (SELECT 1 FROM held_folder_caps hf JOIN folders mf ON mf.id = hf.folder_id
              WHERE nf.path_ids <@ mf.path_ids
                AND (hf.scope = 'identity' OR hf.scope = '*')
                AND (hf.action = 'group' OR hf.action = '*')
                AND (hf.qualifier = 'read' OR hf.qualifier = '*'))
UNION
-- (d) asset folders: asset visible via ACCESS (held ∪ requestable) OR MANAGEMENT
-- (catalog:asset:read on the asset's folder scope) OR CONNECT (an ssh:login on the
-- asset the user entitles over the full asset-scope cascade: global_held ∪ held on
-- the asset object ∪ held on an ancestor-or-self folder). A ** cap normalizes to
-- (*,*,*) and matches ssh:login:L via the column-match, so ** is RETAINED here —
-- matching EntitledLogins on raw CapabilitiesOnScope, exactly as VisibleAssetsUnder.
SELECT DISTINCT a.folder_id AS folder_id
FROM assets a
WHERE a.id = ANY($4::uuid[])
   OR EXISTS (SELECT 1 FROM global_caps c
              WHERE (c.scope = 'catalog' OR c.scope = '*')
                AND (c.action = 'asset' OR c.action = '*')
                AND (c.qualifier = 'read' OR c.qualifier = '*'))
   OR EXISTS (SELECT 1 FROM held_folder_caps hf JOIN folders mf ON mf.id = hf.folder_id
              WHERE (SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id) <@ mf.path_ids
                AND (hf.scope = 'catalog' OR hf.scope = '*')
                AND (hf.action = 'asset' OR hf.action = '*')
                AND (hf.qualifier = 'read' OR hf.qualifier = '*'))
   ` + connectArmExists
	rows, err := s.pool.Query(ctx, query, userID, roleAccess, groupAccess, assetAccess)
	if err != nil {
		return nil, fmt.Errorf("anchor home folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
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
		// Subtree strictly under parent (children only, parent excluded).
		args = append(args, parent)
		level = "f.path_ids <@ (SELECT path_ids FROM folders WHERE id = $3) AND f.id <> $3"
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

// homedLevelPredicate returns the SQL WHERE fragment (over the table alias `n`,
// whose folder column is `folder_id`) that selects the nodes homed under `parent`
// per the (parent, cascade) browse rules — the same four cases nodesHomedUnder
// implements, re-expressed inline so the candidate selection folds into the
// set-based visibility query (no separate round-trip). It appends any needed bind
// value to `args` (starting from placeholder index `next`) and returns the updated
// args plus the placeholder index the caller's own binds continue from.
//
//   - (uuid.Nil, !cascade): folder-less nodes only  → n.folder_id IS NULL.
//   - (uuid.Nil, cascade):  every node              → TRUE.
//   - (parent,   !cascade): homed directly in parent → n.folder_id = $k.
//   - (parent,   cascade):  homed anywhere in the subtree rooted at parent → the
//     node's home folder is a descendant-or-self of parent (ltree <@, GiST-indexed).
func homedLevelPredicate(parent uuid.UUID, cascade bool, args []any, next int) (string, []any, int) {
	switch {
	case parent == uuid.Nil && !cascade:
		return "n.folder_id IS NULL", args, next
	case parent == uuid.Nil && cascade:
		return "TRUE", args, next
	case !cascade:
		args = append(args, parent)
		return fmt.Sprintf("n.folder_id = $%d", next), args, next + 1
	default: // parent set, cascade: home folder in parent's subtree
		args = append(args, parent)
		pred := fmt.Sprintf(
			"n.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = $%d))", next)
		return pred, args, next + 1
	}
}

// mgmtCascadeCTEs is the SHARED management-cascade fragment appended to
// heldPlusGlobalHeldPrefix (which already binds $2/$3/$4 to a mgmtCap's request
// columns and $1 to the user via its closures). It defines two CTEs that decide,
// set-based, whether a folder-homed node is management-visible for that cap — and
// is reused VERBATIM by both visibleHomedSetBased (roles/groups) and
// VisibleAssetsUnder (an asset's NOT-NULL folder is the node folder). Keeping the
// SQL in ONE string is the drift-guard: the asset arm cannot diverge from the
// role/group arm.
//
//   - mgmt_anchor_folders: folders where the user holds mgmtCap directly (held
//     FOLDER closure ⋈ role_capabilities column-match). Management cascades DOWN
//     from these anchors via an ltree <@ join at the call site.
//   - global_mgmt(ok): does the user hold mgmtCap GLOBALLY? (global_held ⋈
//     column-match) — covers folder-less nodes and short-circuits to "manage all".
//
// The three-column glob predicate ((col = $n OR col = '*')) is the same one proven
// ≡ Go CapMatch by TestSQLCapMatchMatchesGo. Leads with `,` so it follows the
// closure prefix; callers append their own `SELECT`.
const mgmtCascadeCTEs = `,
-- folders where the user holds mgmtCap directly (held FOLDER closure + column-match).
-- Management cascades DOWN from these anchors via the ltree <@ join at the call site.
mgmt_anchor_folders AS (
    SELECT DISTINCT h.object_id AS folder_id
    FROM held h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
      AND (rc.scope = $2 OR rc.scope = '*')
      AND (rc.action = $3 OR rc.action = '*')
      AND (rc.qualifier = $4 OR rc.qualifier = '*')
),
-- does the user hold mgmtCap GLOBALLY? (covers folder-less nodes; short-circuit arm)
global_mgmt AS (
    SELECT EXISTS (
        SELECT 1 FROM global_held gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
        WHERE (rc.scope = $2 OR rc.scope = '*')
          AND (rc.action = $3 OR rc.action = '*')
          AND (rc.qualifier = $4 OR rc.qualifier = '*')
    ) AS ok
)`

// connectArmExists is the SHARED SSH-connect-visibility arm: an asset is
// connect-visible iff it declares an ssh_asset_login whose login the user is
// entitled over the FULL asset-scope cascade (global_held ∪ held on the asset
// object ∪ held on an ancestor-or-self folder, via the folders.path_ids @> join).
// It is a bare `OR EXISTS ( ... )` boolean arm and depends only on the asset
// alias `a` (a.id / a.folder_id) being in scope and on the global_held/held CTEs
// from heldPlusGlobalHeldPrefix — it takes NO query params of its own, so both
// call sites (which already provide `a` and the prefix) compose it cleanly.
//
// A `**` cap normalizes to (*,*,*) and matches ssh:login:L via the three-column
// glob predicate, so `**` is deliberately RETAINED here — this mirrors
// EntitledLogins on the RAW CapabilitiesOnScope(AssetScope), NOT ConnectCapabilities.
//
// This is the single source of truth shared by VisibleAssetsUnder and
// anchorHomeFolders so the two security-critical fragments cannot drift — the same
// drift-guard rationale as mgmtCascadeCTEs above.
const connectArmExists = `OR EXISTS (
        SELECT 1 FROM ssh_asset_login sal
        WHERE sal.asset_id = a.id
          AND EXISTS (
              SELECT 1 FROM role_capabilities rc
              WHERE rc.role_id IN (
                    SELECT role_id FROM global_held
                  UNION
                    SELECT h.role_id FROM held h
                    WHERE (h.object_kind = 'asset' AND h.object_id = a.id)
                       OR (h.object_kind = 'folder'
                           AND h.object_id IN (
                               SELECT f.id FROM folders f
                               WHERE f.path_ids @> (
                                   SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id
                               )
                           ))
              )
              AND (rc.scope = 'ssh' OR rc.scope = '*')
              AND (rc.action = 'login' OR rc.action = '*')
              AND (rc.qualifier = sal.login OR rc.qualifier = '*')
          )
   )`

// visibleHomedSetBased is the reusable set-based core behind visibleRolesHomed and
// visibleGroupsHomed (and, via them, the four call sites in the file header). It
// returns the (id, home-folder) rows of `table` homed under `parent` that are
// visible to the user, in ONE query — no per-candidate management round-trip.
//
// `table` is a TRUSTED literal ("roles"/"groups"); `mgmtCap` is the management read
// capability for that kind ("access:role:read" / "identity:group:read"), decomposed
// with NormalizeCap into the ($1s/$1a/$1q) request columns and matched against
// role_capabilities with the SAME three-column glob predicate proven ≡ Go CapMatch
// by TestSQLCapMatchMatchesGo. `accessIDs` is the pre-computed ACCESS set for the
// kind (roles: held ∪ requestable; groups: transitive membership) — passed as a
// uuid[] so the closures that produce it stay one small constant query each rather
// than being re-derived per candidate.
//
// A node is visible iff (union):
//   - ACCESS:     its id is in accessIDs; OR
//   - MANAGEMENT: the user holds mgmtCap on the node's home-folder scope, evaluated
//     set-based via the management-cascade fragment below.
//
// ── Reusable management-cascade fragment (mgmtCascadeCTEs; reused by assets) ──
// Instead of a per-folder CapabilitiesOnScope, whether a node's home folder is
// management-visible for cap C is a single set membership with two arms (the
// shared mgmtCascadeCTEs fragment, also used by VisibleAssetsUnder):
//
//   - GLOBAL arm: the user holds C globally → EXISTS over global_held ⋈
//     role_capabilities with the column-match for C (`global_mgmt.ok`). This alone
//     covers folder-less (folder_id NULL) nodes, which have no folder scope.
//   - FOLDER-CASCADE arm: ∃ a folder F where the user holds C (held FOLDER closure ⋈
//     role_capabilities column-match, → `mgmt_anchor_folders`) AND the node's home
//     folder is a descendant-or-self of F (ltree <@ over the folders' path_ids).
//     Management cascades DOWN the tree, so a cap held at F applies to every node
//     homed at/under F. A NULL home folder matches no anchor → global-only, exactly
//     as the legacy folderManageableFunc treated a nil folder.
//
// The closures come from heldPlusGlobalHeldPrefix (user_groups + held + global_held,
// all composed from the shared closure fragments), so held/global_held here cannot
// drift from Check / CapabilitiesOnScope. Deactivated users are excluded by those
// closures (and by the accessIDs closures), so no extra guard is needed here.
func (s *sqlAuthorizer) visibleHomedSetBased(ctx context.Context, userID uuid.UUID, table, mgmtCap string, parent uuid.UUID, cascade bool, accessIDs []uuid.UUID) ([]nodeFolder, error) {
	reqScope, reqAction, reqQual := NormalizeCap(mgmtCap)
	// $1 user (bound by the closure prefix), $2/$3/$4 the mgmtCap request columns,
	// $5 the access-id set; the level predicate appends its parent bind from $6.
	args := []any{userID, reqScope, reqAction, reqQual, accessIDs}
	level, args, _ := homedLevelPredicate(parent, cascade, args, 6)

	query := heldPlusGlobalHeldPrefix + mgmtCascadeCTEs + `
SELECT n.id, n.folder_id
FROM ` + table + ` n
WHERE (` + level + `)
  AND (
        -- ACCESS axis: pre-computed held ∪ requestable (roles) / membership (groups).
        n.id = ANY($5::uuid[])
        -- MANAGEMENT axis, global arm: mgmtCap held globally ⇒ manage every node.
     OR (SELECT ok FROM global_mgmt)
        -- MANAGEMENT axis, folder-cascade arm: node's home folder is at/under a
        -- folder where the user holds mgmtCap (NULL home ⇒ no match ⇒ global-only).
     OR EXISTS (
            SELECT 1 FROM mgmt_anchor_folders m
            JOIN folders mf ON mf.id = m.folder_id
            JOIN folders nf ON nf.id = n.folder_id
            WHERE nf.path_ids <@ mf.path_ids
        )
      )
ORDER BY n.id`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("visible homed (%s): %w", table, err)
	}
	defer rows.Close()
	var out []nodeFolder
	for rows.Next() {
		var (
			id     uuid.UUID
			folder *uuid.UUID
		)
		if err := rows.Scan(&id, &folder); err != nil {
			return nil, fmt.Errorf("scan visible homed (%s): %w", table, err)
		}
		out = append(out, nodeFolder{ID: id, Folder: folder})
	}
	return out, rows.Err()
}

// visibleRolesHomed returns the roles under `parent` the user may see, each with
// its home folder, applying the full role-visibility predicate (held ∪
// requestable ∪ manageable-via access:role:read). It is the single source of
// truth for that predicate: VisibleRolesUnder maps it to ids, and the folder-anchor
// helper reads its home folders — neither re-implements the predicate.
//
// Set-based: the ACCESS set (held ∪ requestable) is two small constant closure
// queries; the management cascade + candidate selection + union are ONE query via
// visibleHomedSetBased. Total is a small constant, independent of the candidate
// count (no per-folder CapabilitiesOnScope loop).
func (s *sqlAuthorizer) visibleRolesHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	// Access axis: held ∪ requestable, computed once as a single id set.
	held, err := s.heldRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	requestable, err := s.requestableRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := unionKeys(held, requestable)
	return s.visibleHomedSetBased(ctx, userID, "roles", "access:role:read", parent, cascade, accessIDs)
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
	// Access axis: transitive membership, computed once as a single id set.
	member, err := s.memberGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.visibleHomedSetBased(ctx, userID, "groups", "identity:group:read", parent, cascade, mapKeys(member))
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
SELECT DISTINCT h.object_id, rc.scope, rc.action, rc.qualifier
FROM held h JOIN role_capabilities rc ON rc.role_id = h.role_id
WHERE h.object_kind = 'folder'`, userID)
	if err != nil {
		return nil, fmt.Errorf("mgmt scope folders: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			fid        uuid.UUID
			sc, ac, qu string
		)
		if err := rows.Scan(&fid, &sc, &ac, &qu); err != nil {
			return nil, fmt.Errorf("scan mgmt scope: %w", err)
		}
		if isManagementCap(ReconstructCap(sc, ac, qu)) {
			out[fid] = struct{}{}
		}
	}
	return out, rows.Err()
}
