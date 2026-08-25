package authz

// Frozen legacy references for the "authz set-based query rework" (slices B/C).
//
// Each slice rewrites one production method into a single set-based query, gated
// by a differential test asserting the new implementation returns the SAME result
// as the pre-rewrite reference across the seeded probe matrix (setbased_diff_test.go).
// To keep that reference stable AFTER the production method is rewritten, this
// file freezes a VERBATIM copy of the pre-rewrite body under a `*Legacy` name that
// keeps calling the still-in-production helpers (globalHeldCapabilities,
// folderAncestorsAndSelf, capsOnFolders, CapabilitiesOnObject, assetFolderID,
// assetContainerFolderIDs, assetFolders, accessibleAssetSet, assetIDsInFolders,
// assetLoginsFor).
//
// legacyMethods wires these frozen references into the same authzMethods struct
// the harness walks, overriding ONLY the fields a slice has rewritten so far; the
// rest stay bound to the exported (already-verified or not-yet-rewritten) methods.
// Later slices override more fields here.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// capabilitiesOnScopeLegacy is the VERBATIM pre-B2 CapabilitiesOnScope body: the
// 3–5-round-trip fan-out over globalHeldCapabilities + folderAncestorsAndSelf +
// capsOnFolders (+ CapabilitiesOnObject + assetFolderID for assets). It is the
// differential oracle for the set-based rewrite in sql_authorizer.go — the two
// must produce identical Capabilities for every probe.
func (s *sqlAuthorizer) capabilitiesOnScopeLegacy(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error) {
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	switch scope.Kind {
	case ScopeGlobal:
		return global, nil
	case ScopeFolder:
		ancestors, err := s.folderAncestorsAndSelf(ctx, scope.ID)
		if err != nil {
			return nil, fmt.Errorf("folder ancestors: %w", err)
		}
		fcaps, err := s.capsOnFolders(ctx, userID, ancestors)
		if err != nil {
			return nil, err
		}
		return append(global, fcaps...), nil
	case ScopeAsset:
		obj, err := s.CapabilitiesOnObject(ctx, userID, scope.ID, "asset")
		if err != nil {
			return nil, err
		}
		out := append(global, obj...)
		folderID, err := s.assetFolderID(ctx, scope.ID)
		if err != nil {
			// A nonexistent asset resolves to no folder caps (existence-hiding:
			// the handler performs the NotFound check after the cap gate, and
			// CapabilitiesOnObject above already returns empty for it). Any other
			// error is a real failure.
			if errors.Is(err, pgx.ErrNoRows) {
				return out, nil
			}
			return nil, fmt.Errorf("get asset: %w", err)
		}
		ancestors, err := s.folderAncestorsAndSelf(ctx, folderID)
		if err != nil {
			return nil, fmt.Errorf("folder ancestors: %w", err)
		}
		fcaps, err := s.capsOnFolders(ctx, userID, ancestors)
		if err != nil {
			return nil, err
		}
		return append(out, fcaps...), nil
	default:
		return nil, fmt.Errorf("unknown scope kind %d", scope.Kind)
	}
}

// checkLegacy is the VERBATIM pre-B3 Check body: fetch the asset-object held
// closure caps via CapabilitiesOnAsset, then glob-match in Go (CapMatch) via
// Capabilities.Allows. It is the differential oracle for the single-query EXISTS
// rewrite in sql_authorizer.go — the two must agree for every probe.
func (s *sqlAuthorizer) checkLegacy(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	caps, err := s.CapabilitiesOnAsset(ctx, userID, assetID)
	if err != nil {
		return false, err
	}
	return caps.Allows(capability), nil
}

// visibleRolesHomedLegacy is the VERBATIM pre-C1a visibleRolesHomed body: the
// per-candidate loop over nodesHomedUnder("roles", …) that unions the access axis
// (held ∪ requestable, computed once) with a per-home-folder folderManageableFunc
// management check. It is the differential oracle for the set-based rewrite in
// visible_tree.go — the two must return the same roles for every probe.
func (s *sqlAuthorizer) visibleRolesHomedLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
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

// visibleGroupsHomedLegacy is the VERBATIM pre-C1a visibleGroupsHomed body: the
// per-candidate loop over nodesHomedUnder("groups", …) that unions transitive
// membership (computed once) with a per-home-folder folderManageableFunc
// (identity:group:read) management check. Differential oracle for the set-based
// rewrite in visible_tree.go.
func (s *sqlAuthorizer) visibleGroupsHomedLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
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

// visibleRolesUnderLegacy / visibleGroupsUnderLegacy project the frozen homed
// references to id slices, matching VisibleRolesUnder / VisibleGroupsUnder, so the
// differential harness (whose visRoles/visGroups fields return []uuid.UUID) can
// target the legacy predicate directly.
func (s *sqlAuthorizer) visibleRolesUnderLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := s.visibleRolesHomedLegacy(ctx, userID, parent, cascade)
	if err != nil {
		return nil, err
	}
	return nodeIDs(nodes), nil
}

func (s *sqlAuthorizer) visibleGroupsUnderLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := s.visibleGroupsHomedLegacy(ctx, userID, parent, cascade)
	if err != nil {
		return nil, err
	}
	return nodeIDs(nodes), nil
}

// visibleAssetsUnderLegacy is the VERBATIM pre-C1b VisibleAssetsUnder body: the
// per-candidate-folder management loop (folderManageableFunc via
// CapabilitiesOnScope(FolderScope)) plus the per-residual-asset connect loop
// (CapabilitiesOnScope(AssetScope) + EntitledLogins). It is the differential
// oracle for the set-based rewrite in visible_tree.go — the two must return the
// same asset ids for every probe. It keeps calling the still-in-production helpers
// assetContainerFolderIDs / assetFolders / accessibleAssetSet /
// globalHeldCapabilities / CapabilitiesOnScope / assetIDsInFolders / assetLoginsFor.
func (s *sqlAuthorizer) visibleAssetsUnderLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
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

// visibleFoldersUnderLegacy is the VERBATIM pre-C2 VisibleFoldersUnder body: the
// multi-step anchor orchestration (mgmtScopeFolders + visibleRoleHomeFolders +
// visibleGroupHomeFolders + visibleAssetFolders, each re-running overlapping
// closures) followed by ONE visibleFoldersQuery ltree path-reveal. It is the
// differential oracle for the collapsed set-based rewrite in visible_tree.go — the
// two must return the same []VisibleFolder (including the Governed flag) for every
// probe. It keeps calling the still-in-production helpers globalHeldCapabilities /
// allFoldersAtLevel / mgmtScopeFolders / visibleRoleHomeFolders /
// visibleGroupHomeFolders / visibleAssetFolders / unionKeys / mapKeys /
// visibleFoldersQuery.
func (s *sqlAuthorizer) visibleFoldersUnderLegacy(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]VisibleFolder, error) {
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

	// Pass 2 — one ltree query.
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

// folderPathVisibleLegacy is the VERBATIM pre-C2 FolderPathVisible body: the global
// short-circuit, then the asset arm (VisibleAssetsUnder cascade), then (if empty)
// the mgmt+role+group anchor arm + one ltree EXISTS query. It is the differential
// oracle for the collapsed rewrite in visible_tree.go — the two must return the same
// bool for every probe.
func (s *sqlAuthorizer) folderPathVisibleLegacy(ctx context.Context, userID, folderID uuid.UUID) (bool, error) {
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

	assets, err := s.VisibleAssetsUnder(ctx, userID, folderID, true)
	if err != nil {
		return false, err
	}
	if len(assets) > 0 {
		return true, nil
	}

	mgmt, err := s.mgmtScopeFolders(ctx, userID)
	if err != nil {
		return false, err
	}
	roleHomes, err := s.visibleRoleHomeFolders(ctx, userID)
	if err != nil {
		return false, err
	}
	groupHomes, err := s.visibleGroupHomeFolders(ctx, userID)
	if err != nil {
		return false, err
	}
	anchors := unionKeys(mgmt, roleHomes, groupHomes)
	if len(anchors) == 0 {
		return false, nil
	}
	mgmtIDs := mapKeys(mgmt)

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

// ── Frozen-oracle private helpers ───────────────────────────────────────────
//
// The per-item helpers below were the old per-candidate implementations' building
// blocks. Slices B/C replaced their production callers with set-based SQL, leaving
// these referenced ONLY from this frozen oracle (and folder_anchors_test.go). They
// are dead in the production binary, so they live here — retained VERBATIM purely
// to keep the differential tests compiling and passing. They are methods on
// *sqlAuthorizer in package authz; the internal test file can define them.

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

// legacyMethods binds the frozen `*Legacy` references into an authzMethods struct.
// It starts from newMethods (the exported, set-based-target methods) and OVERRIDES
// only the fields rewritten so far — B2 overrides capsOnScope, B3 overrides check,
// C1a overrides visRoles/visGroups. captureAuthzMatrix over legacyMethods therefore
// differs from captureAuthzMatrix over newMethods in exactly the rewritten
// method(s), focusing the differential diff on the rewrite.
func legacyMethods(s *sqlAuthorizer) authzMethods {
	m := newMethods(s)
	m.capsOnScope = s.capabilitiesOnScopeLegacy     // B2
	m.check = s.checkLegacy                         // B3
	m.visRoles = s.visibleRolesUnderLegacy          // C1a
	m.visGroups = s.visibleGroupsUnderLegacy        // C1a
	m.visAssets = s.visibleAssetsUnderLegacy        // C1b
	m.visFolders = s.visibleFoldersUnderLegacy      // C2
	m.folderPathVisible = s.folderPathVisibleLegacy // C2
	return m
}
