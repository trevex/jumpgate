package identity

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// CreateGroup creates a group (optionally folder-homed). A name/sibling collision
// maps to AlreadyExists via apierr.MapWrite.
func (s *Service) CreateGroup(ctx context.Context, folderID pgtype.UUID, name string) (GroupResult, error) {
	g, err := s.q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: name, FolderID: folderID})
	if err != nil {
		return GroupResult{}, apierr.MapWrite(err)
	}
	return s.groupResult(ctx, g)
}

// ResolveGroup resolves a group reference to a group. The reference is one of a
// uuid, a bare name (global group), or `<group>@<folder-path>` (folder-homed). The
// read gate is applied at the resolved group's folder scope, and a read-cap denial
// is existence-hidden as NotFound so a delegated caller cannot learn a group exists
// outside their read scope.
func (s *Service) ResolveGroup(ctx context.Context, caller uuid.UUID, ref string) (GroupResult, error) {
	var grp sqlc.Group
	if id, perr := uuid.Parse(ref); perr == nil {
		g, err := s.q.GetGroup(ctx, id)
		if err != nil {
			return GroupResult{}, apierr.GroupNotFoundOrInternal(err)
		}
		grp = g
	} else if at := strings.LastIndex(ref, "@"); at >= 0 {
		name, folderPath := ref[:at], ref[at+1:]
		folderID, err := resolveFolderIDByPath(ctx, s.q, folderPath)
		if err != nil {
			return GroupResult{}, apierr.GroupNotFoundOrInternal(err)
		}
		g, err := s.q.GetGroupByFolderAndName(ctx, sqlc.GetGroupByFolderAndNameParams{FolderID: pgUUID(folderID), Name: name})
		if err != nil {
			return GroupResult{}, apierr.GroupNotFoundOrInternal(err)
		}
		grp = g
	} else {
		g, err := s.q.GetGroupByNameGlobal(ctx, ref)
		if err != nil {
			return GroupResult{}, apierr.GroupNotFoundOrInternal(err)
		}
		grp = g
	}
	// Existence-hide a read-cap denial as NotFound (must not reveal a group outside
	// the caller's read scope).
	if err := s.requireCap(ctx, caller, "identity:group:read", apiguard.ScopeOfFolderID(grp.FolderID)); err != nil {
		return GroupResult{}, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return s.groupResult(ctx, grp)
}

// ListGroups browses groups under a parent (default root), returning only the
// groups the caller may see — those they are a (transitive) member of, or may manage
// via identity:group:read. Not cap-gated: an unrelated caller sees an empty page,
// not an error. Cascade descends the whole subtree; otherwise only groups homed
// directly in the parent folder (or, for root, folder-less groups). Returns the page
// rows and an opaque next-page token.
func (s *Service) ListGroups(ctx context.Context, caller uuid.UUID, parentRef string, cascade bool, pageSize int32, pageToken string) ([]GroupRow, string, error) {
	parent, err := resolveParentFolderRef(ctx, s.q, parentRef)
	if err != nil {
		return nil, "", err
	}
	ids, err := s.authz.VisibleGroupsUnder(ctx, caller, parent, cascade)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	if len(ids) == 0 {
		return nil, "", nil
	}
	limit := apipage.ClampPageSize(pageSize)
	key, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListGroupsByIDsPagedParams{Column1: ids, Lim: limit}
	if key != nil {
		params.AfterName = pgText(key.Name)
		params.AfterID = pgUUID(key.ID)
	}
	rows, err := s.q.ListGroupsByIDsPaged(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	pathByFolder := map[uuid.UUID]string{}
	out := make([]GroupRow, 0, len(rows))
	for i := range rows {
		row := GroupRow{Group: rows[i]}
		if rows[i].FolderID.Valid {
			fid := apiguard.UUIDFromPg(rows[i].FolderID)
			p, ok := pathByFolder[fid]
			if !ok {
				p, err = s.q.FolderPath(ctx, fid)
				if err != nil {
					return nil, "", connect.NewError(connect.CodeInternal, err)
				}
				pathByFolder[fid] = p
			}
			row.FolderPath = p
		}
		out = append(out, row)
	}
	// Emit a token only when the page was filled (the standard strict-last-page
	// tradeoff). The sort key is name.
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeNameToken(last.Name, last.ID)
	}
	return out, next, nil
}

// AddUserToGroup adds a user as a member of a group. The caller's capability is
// gated by the handler at the group's folder scope.
func (s *Service) AddUserToGroup(ctx context.Context, groupID, userID uuid.UUID) error {
	if err := s.q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: groupID, MemberUserID: pgUUID(userID)}); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// AddGroupToGroup nests one group inside another. Acyclicity: group nesting must
// stay a DAG (the recursive closures are cycle-safe via UNION dedup, but a cycle
// makes membership results surprising). A group can't be a member of itself, and
// making memberGroupID a member of groupID closes a longer cycle iff groupID is
// ALREADY a transitive member of memberGroupID (memberGroupID is a supergroup of
// groupID). Both are refused with FailedPrecondition — a uniform error mirroring the
// folder-move acyclicity guard (the no_self_member DB CHECK is defense-in-depth
// behind this). The caller's capability is gated by the handler.
func (s *Service) AddGroupToGroup(ctx context.Context, groupID, memberGroupID uuid.UUID) error {
	if groupID == memberGroupID {
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("group nesting cycle: a group cannot be a member of itself"))
	}
	var cyclic bool
	if err := s.pool.QueryRow(ctx, `
WITH RECURSIVE supergroups(gid) AS (
    SELECT group_id FROM group_memberships WHERE member_group_id = @groupID
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN supergroups sg ON gm.member_group_id = sg.gid
)
SELECT EXISTS (SELECT 1 FROM supergroups WHERE gid = @memberGroupID)`, pgx.NamedArgs{"groupID": groupID, "memberGroupID": memberGroupID}).Scan(&cyclic); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if cyclic {
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("group nesting cycle: this group is already a transitive member of the group being added"))
	}
	if err := s.q.AddGroupToGroup(ctx, sqlc.AddGroupToGroupParams{GroupID: groupID, MemberGroupID: pgUUID(memberGroupID)}); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group. No-op if absent. The caller's
// capability is gated by the handler.
func (s *Service) RemoveUserFromGroup(ctx context.Context, groupID, userID uuid.UUID) error {
	if err := s.q.RemoveUserFromGroup(ctx, sqlc.RemoveUserFromGroupParams{GroupID: groupID, MemberUserID: pgUUID(userID)}); err != nil {
		return apierr.MapWrite(err)
	}
	return nil
}

// RemoveGroupFromGroup removes a nested group membership. No-op if absent. The
// caller's capability is gated by the handler.
func (s *Service) RemoveGroupFromGroup(ctx context.Context, groupID, memberGroupID uuid.UUID) error {
	if err := s.q.RemoveGroupFromGroup(ctx, sqlc.RemoveGroupFromGroupParams{GroupID: groupID, MemberGroupID: pgUUID(memberGroupID)}); err != nil {
		return apierr.MapWrite(err)
	}
	return nil
}

// ListGroupMembers lists a group's direct member users and member groups with keyset
// pagination over (created_at DESC, id ASC). A single SQL scan covers both
// user-members and group-members; the handler splits the page by which FK column is
// non-null. The next-page token is emitted when the SQL page was full. The caller's
// capability is gated by the handler.
func (s *Service) ListGroupMembers(ctx context.Context, groupID uuid.UUID, pageSize int32, pageToken string) ([]sqlc.GroupMembership, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListGroupMembersPagedParams{GroupID: groupID, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListGroupMembersPaged(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeTimeToken(last.CreatedAt, last.ID)
	}
	return rows, next, nil
}

// GetGroupAccess returns the caller's management capabilities on one group. NotFound
// (existence hiding) when the caller has no relationship to the group — neither a
// capability on its scope nor transitive membership. A member with no management
// capabilities sees an empty capability list (not NotFound).
func (s *Service) GetGroupAccess(ctx context.Context, caller, groupID uuid.UUID) ([]string, error) {
	grp, err := s.q.GetGroup(ctx, groupID)
	if err != nil {
		return nil, apierr.GroupNotFoundOrInternal(err)
	}
	caps, err := s.authz.CapabilitiesOnScope(ctx, caller, apiguard.ScopeOfFolderID(grp.FolderID))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if len(caps) == 0 {
		member, err := s.authz.IsMember(ctx, caller, groupID)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !member {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
		}
	}
	return []string(caps), nil
}

// DeleteGroup deletes a group; memberships, bindings, and policy subjects cascade.
// The caller's capability is gated by the handler at the group's folder scope.
func (s *Service) DeleteGroup(ctx context.Context, groupID uuid.UUID) error {
	if err := s.q.DeleteGroup(ctx, groupID); err != nil {
		return apierr.MapWrite(err)
	}
	return nil
}
