package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Role / group visibility. VisibleRolesUnder and VisibleGroupsUnder unify two
// axes over folder-homed nodes (NULLABLE folder_id, NULL = global/root):
//   - MANAGEMENT: holding the read cap ("access:role:read"/"identity:group:read")
//     OR the subtree-wide "catalog:folder:read" (FolderReadCap, READ-only) at the
//     node's home-folder scope; a global hold covers everything, and a folder-less
//     node is manageable only via that global cap.
//   - ACCESS: a role is visible if held or requestable; a group if the user is a
//     transitive member.
//
// A node is visible on either axis. Deactivated users are excluded by the
// underlying closures (deactivation guard in authz_held, visibleRequestable, and
// memberGroupIDs), so no extra guard is needed here.

// nodeFolder is one folder-homed node: Folder is nil for a global (folder-less)
// node (folder_id IS NULL).
type nodeFolder struct {
	ID     uuid.UUID
	Folder *uuid.UUID
}

// heldRoleIDs returns the role ids the user holds (standing bindings + active
// grants, closed over the role_grants rewrite graph), held on ANY object — one
// arm of the role ACCESS axis.
func (az *Authorizer) heldRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	ids, err := az.queries().HeldRoleIDs(ctx, userID)
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
func (az *Authorizer) requestableRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	reqs, err := az.visibleRequestable(ctx, userID)
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
func (az *Authorizer) IsMember(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
	ok, err := az.queries().IsMember(ctx, sqlc.IsMemberParams{User: uuidArg(userID), Group: uuidArg(groupID)})
	if err != nil {
		return false, fmt.Errorf("is member: %w", err)
	}
	return ok.Bool, nil
}

// memberGroupIDs returns the group ids the user is a transitive member of — the
// group ACCESS axis, via the authz_user_groups closure. The query carries the
// deactivation guard, so a deactivated user yields an empty set.
func (az *Authorizer) memberGroupIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
	ids, err := az.queries().MemberGroupIDs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("member group ids: %w", err)
	}
	out := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		out[uuid.UUID(id.Bytes)] = struct{}{}
	}
	return out, nil
}

// visibleHomedSetBased is the set-based core behind visibleRolesHomed and
// visibleGroupsHomed: it returns the (id, home-folder) rows of `table` homed under
// `parent` visible to the user in ONE query. `table` is a trusted literal
// ("roles"/"groups"); `mgmtCap` is the management read cap, decomposed by
// NormalizeCap and matched against role_capabilities with the three-column glob
// predicate proven ≡ Go CapMatch by TestSQLCapMatchMatchesGo. `accessIDs` is the
// precomputed ACCESS set (roles: held ∪ requestable; groups: membership).
//
// A node is visible iff its id is in accessIDs (ACCESS) OR the user holds mgmtCap
// on the node's home-folder scope (MANAGEMENT). Management cascades DOWN the tree
// via the shared mgmtCascadeCTEs fragment (also used by VisibleAssetsUnder): a
// global-held arm (which covers folder-less nodes) unioned with a folder-cascade
// arm (cap held at F ⇒ every node homed at/under F, via ltree <@). Both arms come
// from authz_held + authz_global_held, so they cannot drift from Check /
// CapabilitiesOnScope, and deactivated users are excluded there.
type homedTable string

const (
	rolesTable  homedTable = "roles"
	groupsTable homedTable = "groups"
)

func (az *Authorizer) visibleHomedSetBased(ctx context.Context, userID uuid.UUID, table homedTable, mgmtCap string, parent uuid.UUID, cascade bool, accessIDs []uuid.UUID) ([]nodeFolder, error) {
	reqScope, reqAction, reqQual := NormalizeCap(mgmtCap)
	// Browse level is selected inside the query by the nullable parent (uuid.Nil ==
	// root/NULL) and cascade args; roles/groups are variants of the same query.
	type homedRow struct {
		id     uuid.UUID
		folder pgtype.UUID
	}
	var rows []homedRow
	switch table {
	case rolesTable:
		rr, err := az.queries().VisibleRolesHomed(ctx, sqlc.VisibleRolesHomedParams{
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
		gr, err := az.queries().VisibleGroupsHomed(ctx, sqlc.VisibleGroupsHomedParams{
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
// its home folder (held ∪ requestable ∪ manageable-via access:role:read). Sole
// owner of the predicate: VisibleRolesUnder maps it to ids and the folder-anchor
// helper reads its home folders.
func (az *Authorizer) visibleRolesHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	// Access axis: held ∪ requestable, computed once as a single id set.
	held, err := az.heldRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	requestable, err := az.requestableRoleIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	accessIDs := unionKeys(held, requestable)
	return az.visibleHomedSetBased(ctx, userID, rolesTable, "access:role:read", parent, cascade, accessIDs)
}

// VisibleRolesUnder returns the role ids under `parent` the user may see
// (held ∪ requestable ∪ manageable-via access:role:read).
func (az *Authorizer) VisibleRolesUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := az.visibleRolesHomed(ctx, userID, parent, cascade)
	if err != nil {
		return nil, err
	}
	return nodeIDs(nodes), nil
}

// visibleGroupsHomed returns the groups under `parent` the user may see, each with
// its home folder (transitive membership ∪ manageable-via identity:group:read).
// Sole owner of the predicate: VisibleGroupsUnder maps it to ids and the
// folder-anchor helper reads its home folders.
func (az *Authorizer) visibleGroupsHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	// Access axis: transitive membership, computed once as a single id set.
	member, err := az.memberGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	return az.visibleHomedSetBased(ctx, userID, groupsTable, "identity:group:read", parent, cascade, mapKeys(member))
}

// VisibleGroupsUnder returns the group ids under `parent` the user may see
// (transitive membership ∪ manageable-via identity:group:read).
func (az *Authorizer) VisibleGroupsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
	nodes, err := az.visibleGroupsHomed(ctx, userID, parent, cascade)
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
