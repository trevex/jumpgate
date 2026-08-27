package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// This file computes the catalog path-reveal anchors that back VisibleFoldersUnder
// and FolderPathVisible: the folder sets whose browse PATH must be revealed and the
// subset of those folders the user actually manages.

// heldRolesAndAssets scans the grant-augmented held closure ONCE and projects both
// arms of the ACCESS axis it carries: the set of role ids the user holds (object
// dimension dropped — held on ANY object) and the set of asset ids the user holds a
// role on directly (object_kind='asset'). Folding both projections into a single
// `held` scan avoids the two separate closure round-trips (heldRoleIDs + the
// VisibleAssets active tier) the legacy anchor path issued.
func (s *Authorizer) heldRolesAndAssets(ctx context.Context, userID uuid.UUID) (roles, assets map[uuid.UUID]struct{}, err error) {
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
func (s *Authorizer) folderAnchors(ctx context.Context, userID uuid.UUID) (anchors, mgmtIDs []uuid.UUID, err error) {
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
func (s *Authorizer) anchorHomeFolders(ctx context.Context, userID uuid.UUID, roleAccess, groupAccess, assetAccess []uuid.UUID) ([]uuid.UUID, error) {
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
func (s *Authorizer) mgmtScopeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
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
