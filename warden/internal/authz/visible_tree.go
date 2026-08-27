package authz

import (
	"fmt"

	"github.com/google/uuid"
)

// This package implements the "visible under a parent" queries that back the
// catalog browse (ListFolders / ListAssets / ListRoles / ListGroups). All unify
// the same two axes:
//
//   - the MANAGEMENT axis: a user who holds "catalog:folder:read" /
//     "catalog:asset:read" (etc.) at a scope may see the folder/asset as an
//     administrator, independent of any access grant. Management authority
//     cascades structurally down the folder tree; the queries evaluate it
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
//
// The concern-specific queries live in visible_assets.go (assets), visible_folders.go
// (folders + path-reveal), homed_nodes.go (roles/groups homed via folder_id), and
// folder_anchors.go (the path-reveal anchor computation). This file holds only the
// shared slice/set helpers used across them.

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
