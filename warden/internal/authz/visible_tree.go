package authz

import (
	"fmt"

	"github.com/google/uuid"
)

// The "visible under a parent" queries back the catalog browse (ListFolders /
// ListAssets / ListRoles / ListGroups). A node is visible on EITHER axis:
//   - MANAGEMENT: holding "catalog:folder:read" / "catalog:asset:read" (etc.) at a
//     scope, independent of any access grant. It cascades structurally down the
//     folder tree, evaluated set-based (the shared mgmtCascadeCTEs fragment: a
//     global-cap arm ∪ an ltree <@ folder-cascade arm), never per-candidate.
//   - ACCESS: an asset the user can reach — VisibleAssets (active or requestable),
//     or CONNECT-visible (the full CapabilitiesOnScope(AssetScope) cascade entitles
//     ≥1 of the asset's SSH logins). A folder is access-visible when its subtree
//     contains such an asset, so the browse path to a reachable asset is not hidden.
//
// Deactivated users are excluded by the underlying closures (authz_held /
// authz_global_held / VisibleAssets), so no extra guard is needed here.
//
// Concern-specific queries live in visible_assets.go, visible_folders.go,
// homed_nodes.go, and folder_anchors.go; this file holds only the shared
// slice/set helpers.

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
