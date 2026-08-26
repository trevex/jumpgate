package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
// are handled by the underlying closures (authz_held / authz_global_held /
// VisibleAssets all exclude a deactivated user), so no extra guard is needed here for the
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
SELECT id FROM folders WHERE parent_id IS NOT DISTINCT FROM @parent ORDER BY name, id`, pgx.NamedArgs{"parent": arg})
	if err != nil {
		return nil, fmt.Errorf("child folders: %w", err)
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
SELECT asset_id, login FROM ssh_asset_login WHERE asset_id = ANY(@assetIDs::uuid[]) ORDER BY login`, pgx.NamedArgs{"assetIDs": assetIDs})
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
// selection, management cascade, and connect cascade are ONE query over
// authz_held + authz_global_held. Total is a small constant — no per-folder and no
// per-residual-asset CapabilitiesOnScope loop.
//
// An asset (whose folder is in scope under `parent`) is visible iff ANY of:
//
//   - ACCESS:     a.id ∈ VisibleAssets(user) (a.id = ANY(@accessIDs)); OR
//   - MANAGEMENT: the user holds "catalog:asset:read" on the asset's folder scope —
//     GLOBAL (global_mgmt.ok) covers every asset, else the asset's folder is a
//     descendant-or-self of a folder where the cap is held (mgmt_anchor_folders,
//     the shared mgmtCascadeCTEs fragment with the asset's NOT-NULL folder as the
//     node folder); OR
//   - CONNECT:    the asset declares ≥1 SSH login L (ssh_asset_login) that the user
//     entitles over the FULL asset-scope cascade — a role in authz_global_held, held on
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
	// constant closure pair, collapsed into a uuid[] param (@accessIDs).
	accessible, err := s.accessibleAssetSet(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := make([]uuid.UUID, 0, len(accessible))
	for id := range accessible {
		accessIDs = append(accessIDs, id)
	}

	// The management cascade uses the catalog:asset:read request columns; the
	// browse level is selected by the nullable parent (uuid.Nil == root/NULL) and
	// cascade args inside the query. The connect axis is retained verbatim (a `**`
	// cap normalizes to (*,*,*) and matches ssh:login:L via the column-match).
	reqScope, reqAction, reqQual := NormalizeCap("catalog:asset:read")
	ids, err := s.queries().VisibleAssetsUnder(ctx, sqlc.VisibleAssetsUnderParams{
		User:      userID,
		Parent:    nullableUUIDArg(parent),
		Cascade:   cascade,
		CapScope:  reqScope,
		CapAction: reqAction,
		CapQual:   reqQual,
		AccessIds: accessIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("visible assets under: %w", err)
	}
	return ids, nil
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
	sql, na := s.visibleFoldersQuery(parent, cascade, anchors, mgmtIDs)
	rows, err := s.pool.Query(ctx, sql, na)
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
			`SELECT EXISTS(SELECT 1 FROM folders WHERE id = @folderID)`, pgx.NamedArgs{"folderID": folderID}).Scan(&exists); err != nil {
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
WITH f  AS (SELECT path_ids FROM folders WHERE id = @folderID),
     ap AS (SELECT path_ids FROM folders WHERE id = ANY(@anchors::uuid[])),
     mp AS (SELECT path_ids FROM folders WHERE id = ANY(@mgmtIDs::uuid[]))
SELECT EXISTS (SELECT 1 FROM f, ap WHERE f.path_ids @> ap.path_ids)
    OR EXISTS (SELECT 1 FROM f, mp WHERE f.path_ids <@ mp.path_ids)`,
		pgx.NamedArgs{"folderID": folderID, "anchors": anchors, "mgmtIDs": mgmtIDs}).Scan(&vis)
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
	rows, err := s.queries().HeldRolesAndAssets(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("held roles and assets: %w", err)
	}
	roles = map[uuid.UUID]struct{}{}
	assets = map[uuid.UUID]struct{}{}
	for _, row := range rows {
		roles[uuid.UUID(row.RoleID.Bytes)] = struct{}{}
		if row.ObjectKind.String == "asset" {
			assets[uuid.UUID(row.ObjectID.Bytes)] = struct{}{}
		}
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
	// the shared authz_held/authz_global_held closures) — and, for assets, ∪ (CONNECT via an
	// ssh:login the user entitles over the full asset-scope cascade). The mgmt read
	// caps are 3-segment concrete (access:role:read / identity:group:read /
	// catalog:asset:read), so their columns are literals; the three-column glob
	// predicate ((col = literal OR col = '*')) is the same one proven ≡ Go CapMatch by
	// TestSQLCapMatchMatchesGo.
	//
	// @user (bound by the closure prefix); @roleAccess role-access ids; @groupAccess
	// group-access ids; @assetAccess asset-access ids.
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
// (MANAGEMENT via the kind's read cap over the shared authz_held/authz_global_held closures) —
// plus, for assets, the CONNECT arm (an ssh:login the user entitles over the full
// asset-scope cascade). It reuses authz_held + authz_global_held so the closures
// cannot drift from Check / CapabilitiesOnScope;
// deactivated users are excluded by those closures and by the ACCESS closures that
// produced the id params.
//
//   - @user (bound by the closure prefix);
//   - @roleAccess role-access ids; @groupAccess group-access ids; @assetAccess asset-access ids.
func (s *sqlAuthorizer) anchorHomeFolders(ctx context.Context, userID uuid.UUID, roleAccess, groupAccess, assetAccess []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.queries().AnchorHomeFolders(ctx, sqlc.AnchorHomeFoldersParams{
		User:        userID,
		RoleAccess:  roleAccess,
		GroupAccess: groupAccess,
		AssetAccess: assetAccess,
	})
	if err != nil {
		return nil, fmt.Errorf("anchor home folders: %w", err)
	}
	out := make([]uuid.UUID, 0, len(rows))
	for _, id := range rows {
		out = append(out, uuid.UUID(id.Bytes))
	}
	return out, nil
}

// visibleFoldersQuery builds the single-query, two-anchor-set path-reveal SELECT
// used by VisibleFoldersUnder. `anchors` are the folders whose path must be
// revealed (ancestor-or-self); `mgmtIDs` are the folders the user manages (their
// subtrees are visible AND governed). The `<LEVEL>` predicate is inlined per the
// (parent, cascade) case exactly as childCandidateFolderIDs computes the browse
// level; a nil `parent` is bound as SQL NULL via `parent_id IS NOT DISTINCT FROM`
// (matching childFolderIDs) or, for cascade, means the whole tree (no predicate).
func (s *sqlAuthorizer) visibleFoldersQuery(parent uuid.UUID, cascade bool, anchors, mgmtIDs []uuid.UUID) (string, pgx.NamedArgs) {
	// @anchors, @mgmtIDs; @parent (when present) is the parent binding.
	na := pgx.NamedArgs{"anchors": anchors, "mgmtIDs": mgmtIDs}
	var level string
	switch {
	case cascade && parent == uuid.Nil:
		// Whole tree: every folder is at the level.
		level = "TRUE"
	case cascade:
		// Subtree strictly under parent (children only, parent excluded).
		na["parent"] = parent
		level = "f.path_ids <@ (SELECT path_ids FROM folders WHERE id = @parent) AND f.id <> @parent"
	case parent == uuid.Nil:
		// Direct children of the root (parent_id IS NULL), bound NULL-safe.
		na["parent"] = (*uuid.UUID)(nil)
		level = "f.parent_id IS NOT DISTINCT FROM @parent"
	default:
		// Direct children of parent.
		na["parent"] = parent
		level = "f.parent_id IS NOT DISTINCT FROM @parent"
	}
	sql := `
WITH anchor_paths AS (SELECT path_ids FROM folders WHERE id = ANY(@anchors::uuid[])),
     mgmt_paths   AS (SELECT path_ids FROM folders WHERE id = ANY(@mgmtIDs::uuid[]))
SELECT f.id,
       EXISTS (SELECT 1 FROM mgmt_paths m WHERE f.path_ids <@ m.path_ids) AS governed
FROM folders f
WHERE ` + level + `
  AND ( EXISTS (SELECT 1 FROM anchor_paths a WHERE f.path_ids @> a.path_ids)
     OR EXISTS (SELECT 1 FROM mgmt_paths  m WHERE f.path_ids <@ m.path_ids) )
ORDER BY f.name, f.id`
	return sql, na
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
// Deactivated users are excluded by the underlying closures: authz_held and
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
	ids, err := s.queries().HeldRoleIDs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("held role ids: %w", err)
	}
	out := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		out[uuid.UUID(id.Bytes)] = struct{}{}
	}
	return out, nil
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
	ok, err := s.queries().IsMember(ctx, sqlc.IsMemberParams{User: uuidArg(userID), Group: uuidArg(groupID)})
	if err != nil {
		return false, fmt.Errorf("is member: %w", err)
	}
	return ok.Bool, nil
}

// memberGroupIDs returns the set of group ids the user is a (transitive) member
// of — the group ACCESS axis. It reaches the authz_user_groups SQL function (the
// same transitive group-membership closure authz_held / authz_global_held use)
// via the MemberGroupIDs query.
//
// The query carries the deactivation guard (authz_user_is_active), matching the
// predicate in authz_held and authz_global_held: a deactivated user therefore
// yields an empty set.
func (s *sqlAuthorizer) memberGroupIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	ids, err := s.queries().MemberGroupIDs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("member group ids: %w", err)
	}
	out := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		out[uuid.UUID(id.Bytes)] = struct{}{}
	}
	return out, nil
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

// visibleHomedSetBased is the reusable set-based core behind visibleRolesHomed and
// visibleGroupsHomed (and, via them, the four call sites in the file header). It
// returns the (id, home-folder) rows of `table` homed under `parent` that are
// visible to the user, in ONE query — no per-candidate management round-trip.
//
// `table` is a TRUSTED literal ("roles"/"groups"); `mgmtCap` is the management read
// capability for that kind ("access:role:read" / "identity:group:read"), decomposed
// with NormalizeCap into the (@capScope/@capAction/@capQual) request columns and
// matched against role_capabilities with the SAME three-column glob predicate proven ≡ Go CapMatch
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
//   - GLOBAL arm: the user holds C globally → EXISTS over authz_global_held ⋈
//     role_capabilities with the column-match for C (`global_mgmt.ok`). This alone
//     covers folder-less (folder_id NULL) nodes, which have no folder scope.
//   - FOLDER-CASCADE arm: ∃ a folder F where the user holds C (held FOLDER closure ⋈
//     role_capabilities column-match, → `mgmt_anchor_folders`) AND the node's home
//     folder is a descendant-or-self of F (ltree <@ over the folders' path_ids).
//     Management cascades DOWN the tree, so a cap held at F applies to every node
//     homed at/under F. A NULL home folder matches no anchor → global-only, exactly
//     as the legacy folderManageableFunc treated a nil folder.
//
// The closures come from authz_held + authz_global_held, so the management arms
// here cannot drift from Check / CapabilitiesOnScope. Deactivated users are excluded by those
// closures (and by the accessIDs closures), so no extra guard is needed here.
type homedTable string

const (
	rolesTable  homedTable = "roles"
	groupsTable homedTable = "groups"
)

func (s *sqlAuthorizer) visibleHomedSetBased(ctx context.Context, userID uuid.UUID, table homedTable, mgmtCap string, parent uuid.UUID, cascade bool, accessIDs []uuid.UUID) ([]nodeFolder, error) {
	reqScope, reqAction, reqQual := NormalizeCap(mgmtCap)
	// The management cascade uses the mgmtCap request columns; the browse level is
	// selected inside the query by the nullable parent (uuid.Nil == root/NULL) and
	// cascade args. roles/groups are distinct table variants of the same query.
	type homedRow struct {
		id     uuid.UUID
		folder pgtype.UUID
	}
	var rows []homedRow
	switch table {
	case rolesTable:
		rr, err := s.queries().VisibleRolesHomed(ctx, sqlc.VisibleRolesHomedParams{
			User: userID, Parent: nullableUUIDArg(parent), Cascade: cascade,
			CapScope: reqScope, CapAction: reqAction, CapQual: reqQual, AccessIds: accessIDs,
		})
		if err != nil {
			return nil, fmt.Errorf("visible homed (%s): %w", table, err)
		}
		for _, r := range rr {
			rows = append(rows, homedRow{id: r.ID, folder: r.FolderID})
		}
	case groupsTable:
		gr, err := s.queries().VisibleGroupsHomed(ctx, sqlc.VisibleGroupsHomedParams{
			User: userID, Parent: nullableUUIDArg(parent), Cascade: cascade,
			CapScope: reqScope, CapAction: reqAction, CapQual: reqQual, AccessIds: accessIDs,
		})
		if err != nil {
			return nil, fmt.Errorf("visible homed (%s): %w", table, err)
		}
		for _, r := range gr {
			rows = append(rows, homedRow{id: r.ID, folder: r.FolderID})
		}
	default:
		return nil, fmt.Errorf("unknown homed table %q", table)
	}
	out := make([]nodeFolder, 0, len(rows))
	for _, r := range rows {
		var folder *uuid.UUID
		if r.folder.Valid {
			f := uuid.UUID(r.folder.Bytes)
			folder = &f
		}
		out = append(out, nodeFolder{ID: r.id, Folder: folder})
	}
	return out, nil
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
	return s.visibleHomedSetBased(ctx, userID, rolesTable, "access:role:read", parent, cascade, accessIDs)
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
	return s.visibleHomedSetBased(ctx, userID, groupsTable, "identity:group:read", parent, cascade, mapKeys(member))
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
// Capabilities come from the role_capabilities (scope, action, qualifier) columns
// joined to the held closure; each row is reconstructed via ReconstructCap and
// classified by isManagementCap in Go (the `*`/`**`-yes-but-`*:connect`-no rule is
// too subtle to translate into a column predicate).
func (s *sqlAuthorizer) mgmtScopeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := s.queries().HeldFolderCapabilities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mgmt scope folders: %w", err)
	}
	out := map[uuid.UUID]struct{}{}
	for _, row := range rows {
		if isManagementCap(ReconstructCap(row.Scope, row.Action, row.Qualifier)) {
			out[uuid.UUID(row.ObjectID.Bytes)] = struct{}{}
		}
	}
	return out, nil
}
