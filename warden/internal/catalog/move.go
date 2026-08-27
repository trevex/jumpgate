package catalog

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ancestorSet returns folderID together with all of its ancestors up to the root as
// a set, for a containment membership test.
func ancestorSet(ctx context.Context, q *sqlc.Queries, folderID uuid.UUID) (map[uuid.UUID]bool, error) {
	ids, err := q.FolderAncestorsAndSelf(ctx, folderID)
	if err != nil {
		return nil, err
	}
	set := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

// homeContained reports whether a role whose home folder is roleHome would remain
// contained by a scope whose (post-move) ancestor set is targetAncestors. A global
// role (invalid home) is never a containment constraint.
func homeContained(roleHome pgtype.UUID, targetAncestors map[uuid.UUID]bool) bool {
	if !roleHome.Valid {
		return true
	}
	return targetAncestors[uuid.UUID(roleHome.Bytes)]
}

// roleHome returns a role's home folder (invalid pgtype.UUID for a global role).
func (s *Service) roleHome(ctx context.Context, q *sqlc.Queries, roleID uuid.UUID) (pgtype.UUID, error) {
	r, err := q.GetRole(ctx, roleID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return r.FolderID, nil
}

// roleRefsOfPolicy collects the role ids a policy references: the granted role plus
// its optional requester and approver roles. Each is subject to the containment
// invariant when the policy's scope moves.
func roleRefsOfPolicy(p sqlc.RequestPolicy) []uuid.UUID {
	ids := []uuid.UUID{p.RoleID}
	if p.RequesterRoleID.Valid {
		ids = append(ids, uuid.UUID(p.RequesterRoleID.Bytes))
	}
	if p.ApproverRoleID.Valid {
		ids = append(ids, uuid.UUID(p.ApproverRoleID.Bytes))
	}
	return ids
}

// validateAssetMove denies (FailedPrecondition) if moving assetID into destFolder
// would leave any binding or policy scoped to that asset granting a folder-scoped
// role whose home no longer contains the asset's new location.
func (s *Service) validateAssetMove(ctx context.Context, q *sqlc.Queries, assetID, destFolder uuid.UUID) error {
	destAnc, err := ancestorSet(ctx, q, destFolder)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	bindings, err := q.ListRoleBindingsByAsset(ctx, pgconv.UUID(assetID))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for _, b := range bindings {
		home, err := s.roleHome(ctx, q, b.RoleID)
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		if !homeContained(home, destAnc) {
			return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("binding %s grants a folder-scoped role not containing the destination", b.ID))
		}
	}
	policies, err := q.ListRequestPoliciesByAsset(ctx, pgconv.UUID(assetID))
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for _, p := range policies {
		for _, rid := range roleRefsOfPolicy(p) {
			home, err := s.roleHome(ctx, q, rid)
			if err != nil {
				return connect.NewError(connect.CodeInternal, err)
			}
			if !homeContained(home, destAnc) {
				return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("policy %s references a folder-scoped role not containing the destination", p.ID))
			}
		}
	}
	return nil
}

// validateFolderMove denies (FailedPrecondition) if reparenting movedFolder under
// newParent would break the containment invariant for any binding/policy scoped to a
// folder or asset within the moved subtree. An invalid newParent means a move to the
// root (no parent), whose above-portion is the empty set — which NARROWS ancestors
// and can break containment, so it must be validated like any other move.
//
// Only entities in the moved subtree are affected; the subtree's own internal
// structure is unchanged. So a scope node's post-move ancestor set is computed as:
//
//	newAnc(node) = (currentAncestorSet(node) ∩ sub) ∪ ancestors-and-self(newParent)
//
// The first term is exactly the in-subtree portion (movedFolder and below); the
// second is the new above-portion contributed by the destination parent (empty for a
// root move). For every affected binding/policy, every referenced folder-scoped
// role's home must lie in its scope node's newAnc, else the move is denied.
func (s *Service) validateFolderMove(ctx context.Context, q *sqlc.Queries, movedFolder uuid.UUID, newParent pgtype.UUID) error {
	subList, err := q.FolderSubtreeIDs(ctx, movedFolder)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	sub := make(map[uuid.UUID]bool, len(subList))
	for _, id := range subList {
		sub[id] = true
	}
	// ancestors-and-self of the new parent; the empty set for a root move (no parent).
	parentAnc := map[uuid.UUID]bool{}
	if newParent.Valid {
		parentAnc, err = ancestorSet(ctx, q, uuid.UUID(newParent.Bytes))
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
	}

	// Assets in the moved subtree: id -> containing folder, so an asset-scoped
	// binding/policy resolves to its (unchanged) folder node for the newAnc test.
	assetRows, err := q.AssetIDsInFolders(ctx, subList)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	assetFolder := make(map[uuid.UUID]uuid.UUID, len(assetRows))
	assetIDs := make([]uuid.UUID, 0, len(assetRows))
	for _, a := range assetRows {
		assetFolder[a.ID] = a.FolderID
		assetIDs = append(assetIDs, a.ID)
	}

	// newAnc computes a scope node folder's post-move ancestor set, memoized.
	newAncCache := make(map[uuid.UUID]map[uuid.UUID]bool)
	newAnc := func(node uuid.UUID) (map[uuid.UUID]bool, error) {
		if got, ok := newAncCache[node]; ok {
			return got, nil
		}
		cur, err := ancestorSet(ctx, q, node)
		if err != nil {
			return nil, err
		}
		out := make(map[uuid.UUID]bool, len(cur)+len(parentAnc))
		for id := range cur {
			if sub[id] { // keep only the in-subtree portion
				out[id] = true
			}
		}
		for id := range parentAnc { // union the new above-portion
			out[id] = true
		}
		newAncCache[node] = out
		return out, nil
	}

	// scopeNode maps a binding/policy's scope columns to the folder node whose
	// post-move ancestors gate containment: the scope folder itself, or an
	// asset-scoped binding's containing folder.
	scopeNode := func(scopeFolder, scopeAsset pgtype.UUID) (uuid.UUID, bool) {
		if scopeFolder.Valid {
			return uuid.UUID(scopeFolder.Bytes), true
		}
		if scopeAsset.Valid {
			if f, ok := assetFolder[uuid.UUID(scopeAsset.Bytes)]; ok {
				return f, true
			}
		}
		return uuid.Nil, false
	}

	bindings, err := q.BindingsScopedToFoldersOrAssets(ctx, sqlc.BindingsScopedToFoldersOrAssetsParams{
		Column1: subList, Column2: assetIDs,
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for _, b := range bindings {
		node, ok := scopeNode(b.ScopeFolderID, b.ScopeAssetID)
		if !ok {
			continue
		}
		anc, err := newAnc(node)
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		home, err := s.roleHome(ctx, q, b.RoleID)
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		if !homeContained(home, anc) {
			return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("binding %s grants a folder-scoped role not containing its post-move scope", b.ID))
		}
	}

	policies, err := q.PoliciesScopedToFoldersOrAssets(ctx, sqlc.PoliciesScopedToFoldersOrAssetsParams{
		Column1: subList, Column2: assetIDs,
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	for _, p := range policies {
		node, ok := scopeNode(p.ScopeFolderID, p.ScopeAssetID)
		if !ok {
			continue
		}
		anc, err := newAnc(node)
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		for _, rid := range roleRefsOfPolicy(p) {
			home, err := s.roleHome(ctx, q, rid)
			if err != nil {
				return connect.NewError(connect.CodeInternal, err)
			}
			if !homeContained(home, anc) {
				return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("policy %s references a folder-scoped role not containing its post-move scope", p.ID))
			}
		}
	}
	return nil
}
