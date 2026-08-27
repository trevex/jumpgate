package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// Home-folder anchor helpers used by folder_anchors_test.go. They compose the
// production visibility methods (visibleRolesHomed / visibleGroupsHomed /
// VisibleAssetsUnder) and reduce them to the set of folders that anchor
// path-reveal down to a visible node — the reference against which the combined
// anchor query (mgmtScopeFolders / anchorHomeFolders) is asserted.

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
func (az *Authorizer) visibleRoleHomeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	nodes, err := az.visibleRolesHomed(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	return nodeHomeFolders(nodes), nil
}

// visibleGroupHomeFolders returns the set of home folders of every group visible to
// the user (whole-tree cascade). These folders anchor path-reveal so the browse
// path down to a visible group is never hidden.
func (az *Authorizer) visibleGroupHomeFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	nodes, err := az.visibleGroupsHomed(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	return nodeHomeFolders(nodes), nil
}

// visibleAssetFolders returns the home folders of every asset visible to the user
// (the full VisibleAssetsUnder union: access ∪ management ∪ connect, whole-tree
// cascade). These folders anchor the path down to a reachable asset.
func (az *Authorizer) visibleAssetFolders(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	assetIDs, err := az.VisibleAssetsUnder(ctx, userID, uuid.Nil, true)
	if err != nil {
		return nil, err
	}
	if len(assetIDs) == 0 {
		return map[uuid.UUID]struct{}{}, nil
	}
	rows, err := az.pool.Query(ctx, `SELECT DISTINCT folder_id FROM assets WHERE id = ANY($1::uuid[])`, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("visible asset folders: %w", err)
	}
	defer rows.Close()
	return scanUUIDSet(rows)
}
