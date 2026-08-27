package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

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
func (s *Authorizer) heldRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
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
func (s *Authorizer) requestableRoleIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
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
func (s *Authorizer) IsMember(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
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
func (s *Authorizer) memberGroupIDs(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]struct{}, error) {
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

func (s *Authorizer) visibleHomedSetBased(ctx context.Context, userID uuid.UUID, table homedTable, mgmtCap string, parent uuid.UUID, cascade bool, accessIDs []uuid.UUID) ([]nodeFolder, error) {
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
func (s *Authorizer) visibleRolesHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
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
func (s *Authorizer) VisibleRolesUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
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
func (s *Authorizer) visibleGroupsHomed(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]nodeFolder, error) {
	// Access axis: transitive membership, computed once as a single id set.
	member, err := s.memberGroupIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.visibleHomedSetBased(ctx, userID, groupsTable, "identity:group:read", parent, cascade, mapKeys(member))
}

// VisibleGroupsUnder returns the group ids under `parent` the user may see. See
// the Authorizer interface for the visibility predicate.
func (s *Authorizer) VisibleGroupsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error) {
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
