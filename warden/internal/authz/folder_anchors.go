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
// ACCESS arms it carries: the role ids the user holds (on ANY object) and the asset
// ids the user holds a role on directly (object_kind='asset').
func (az *Authorizer) heldRolesAndAssets(ctx context.Context, userID uuid.UUID) (roles, assets map[uuid.UUID]struct{}, err error) {
	rows, err := az.queries().HeldRolesAndAssets(ctx, userID)
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

// folderAnchors computes the two folder sets that drive the catalog path-reveal
// (VisibleFoldersUnder / FolderPathVisible):
//   - anchors: the union of four sources (management-scope folders ∪ home folders of
//     visible roles ∪ home folders of visible groups ∪ folders of visible assets) —
//     the folders whose browse PATH must be revealed (ancestor-or-self).
//   - mgmtIDs: the folders the user MANAGES — the set whose subtrees
//     VisibleFoldersUnder marks `governed`. mgmtIDs ⊆ anchors.
//
// Each shared closure is evaluated ONCE and the home-folder anchors resolved by one
// combined query. The governed set stays classified in Go over mgmtScopeFolders:
// its isManagementCap predicate (admits `*`/`**` but NOT a scope='*' connect
// pattern) is subtler than a SQL scope predicate.
func (az *Authorizer) folderAnchors(ctx context.Context, userID uuid.UUID) (anchors, mgmtIDs []uuid.UUID, err error) {
	// Shared ACCESS closures, each evaluated once.
	heldRoles, heldAssets, err := az.heldRolesAndAssets(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	// requestable feeds both the requestable-role and requestable-asset arms.
	req, err := az.visibleRequestable(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	// member: transitive group membership — one closure.
	member, err := az.memberGroupIDs(ctx, userID)
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
	mgmt, err := az.mgmtScopeFolders(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	mgmtIDs = mapKeys(mgmt)

	// Combined anchor query: role/group/asset home-folder anchors in ONE go.
	anchorFolders, err := az.anchorHomeFolders(ctx, userID, mapKeys(roleAccess), mapKeys(member), mapKeys(assetAccess))
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
// folder-id anchor sources hanging off folder-homed nodes: the home folders of
// visible roles/groups and the folders of visible assets. Visibility per kind is
// the precomputed ACCESS id set ∪ MANAGEMENT (the kind's read cap) — plus, for
// assets, CONNECT (an ssh:login the user entitles over the full asset-scope
// cascade). It reuses authz_held + authz_global_held, so the closures cannot drift
// from Check / CapabilitiesOnScope and deactivated users are excluded there.
func (az *Authorizer) anchorHomeFolders(ctx context.Context, userID uuid.UUID, roleAccess, groupAccess, assetAccess []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := az.queries().AnchorHomeFolders(ctx, sqlc.AnchorHomeFoldersParams{
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

// isManagementCap reports whether a capability pattern grants management (vs pure
// connect): anything under catalog:/access:/identity: or the broad `**` admin
// wildcard. A bare ssh:* is connect and does NOT anchor a folder. A bare `*` is
// matched defensively but inert (it matches one segment, never crosses `:`, and is
// rejected at CreateRole).
func isManagementCap(pat string) bool {
	if pat == "**" || pat == "*" {
		return true
	}
	return strings.HasPrefix(pat, "catalog:") ||
		strings.HasPrefix(pat, "access:") ||
		strings.HasPrefix(pat, "identity:")
}

// mgmtScopeFolders returns the folder scopes at which the user holds a role
// granting a management capability. Bounded by the held folder-bindings closure;
// each row is reconstructed and classified by isManagementCap in Go (the
// `*`/`**`-yes-but-`*:connect`-no rule is too subtle for a column predicate). These
// folders are both a path-reveal anchor source and the governed set: a folder is
// governed iff it is at/under one of these scopes.
func (az *Authorizer) mgmtScopeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	rows, err := az.queries().HeldFolderCapabilities(ctx, userID)
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
