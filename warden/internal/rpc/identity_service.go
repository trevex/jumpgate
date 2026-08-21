package rpc

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// grantRevoker revokes a user's active JIT grants. Satisfied by
// accessrequest.Service; declared here as a narrow interface so the identity
// handler depends only on the capability it needs (and to keep the seam obvious).
type grantRevoker interface {
	RevokeGrantsForUser(ctx context.Context, actor, userID uuid.UUID, reason string) (int, error)
}

// sessionEvictor force-terminates all of a user's live sessions. Satisfied by
// *dataplane.Terminator; a narrow seam so the identity handler depends only on
// the capability it needs.
type sessionEvictor interface {
	TerminateUser(ctx context.Context, userID uuid.UUID, reason string) (int, error)
}

// IdentityServer implements identityv1connect.IdentityServiceHandler.
type IdentityServer struct {
	q       *gen.Queries
	tokens  *auth.TokenService
	revoker grantRevoker
	evictor sessionEvictor
	capGuard
}

// NewIdentityServer constructs the IdentityService implementation. revoker is
// used by DeactivateUser to cascade grant revocation and evictor to force-evict
// the user's remaining live sessions; either may be nil in tests that don't
// exercise deactivation teardown.
func NewIdentityServer(q *gen.Queries, tokens *auth.TokenService, revoker grantRevoker, evictor sessionEvictor, a authz.Authorizer) *IdentityServer {
	return &IdentityServer{q: q, tokens: tokens, revoker: revoker, evictor: evictor, capGuard: capGuard{authz: a, q: q}}
}

func toUserMsg(u gen.User) *identityv1.User {
	return &identityv1.User{Id: u.ID.String(), Email: u.Email, DisplayName: u.DisplayName}
}

func toGroupMsg(g gen.Group) *identityv1.Group {
	return &identityv1.Group{Id: g.ID.String(), Name: g.Name, FolderId: pgUUIDToString(g.FolderID)}
}

// groupMsgWithPath fills folder_path (empty for global) for single-group responses.
func (s *IdentityServer) groupMsgWithPath(ctx context.Context, g gen.Group) (*identityv1.Group, error) {
	m := toGroupMsg(g)
	if g.FolderID.Valid {
		fp, err := s.q.FolderPath(ctx, uuidFromPg(g.FolderID))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		m.FolderPath = fp
	}
	return m, nil
}

func pgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// CreateUser creates a local user (admin only).
func (s *IdentityServer) CreateUser(ctx context.Context, req *connect.Request[identityv1.CreateUserRequest]) (*connect.Response[identityv1.CreateUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:create", authz.GlobalScope()); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	u, err := s.q.CreateUserFull(ctx, gen.CreateUserFullParams{
		Email: req.Msg.Email, DisplayName: req.Msg.DisplayName,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("email already exists"))
	}
	if err := s.q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.CreateUserResponse{User: toUserMsg(u)}), nil
}

// GetUser returns a user by ID (admin only). Unknown IDs return NotFound.
func (s *IdentityServer) GetUser(ctx context.Context, req *connect.Request[identityv1.GetUserRequest]) (*connect.Response[identityv1.GetUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return connect.NewResponse(&identityv1.GetUserResponse{User: toUserMsg(u)}), nil
}

// ResolveUser resolves a user email to an id (admin only). Unknown emails return NotFound.
func (s *IdentityServer) ResolveUser(ctx context.Context, req *connect.Request[identityv1.ResolveUserRequest]) (*connect.Response[identityv1.ResolveUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	u, err := s.q.GetUserByEmail(ctx, req.Msg.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.ResolveUserResponse{UserId: u.ID.String()}), nil
}

// ListUsers returns a page of users (admin only), ordered by (email ASC, id ASC).
func (s *IdentityServer) ListUsers(ctx context.Context, req *connect.Request[identityv1.ListUsersRequest]) (*connect.Response[identityv1.ListUsersResponse], error) {
	if err := s.requireCap(ctx, "identity:user:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListUsersParams{Lim: limit}
	if k != nil {
		params.AfterEmail = pgtype.Text{String: k.Name, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListUsers(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &identityv1.ListUsersResponse{}
	for i := range rows {
		out.Users = append(out.Users, toUserMsg(rows[i]))
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// costs one extra empty trailing page (standard strict-last-page tradeoff).
	// encodeNameToken takes the SORT-KEY column: email here.
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeNameToken(last.Email, last.ID)
	}
	return connect.NewResponse(out), nil
}

// CreateGroup creates a group (admin only).
func (s *IdentityServer) CreateGroup(ctx context.Context, req *connect.Request[identityv1.CreateGroupRequest]) (*connect.Response[identityv1.CreateGroupResponse], error) {
	folderID, _, err := optUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	if err := s.requireCap(ctx, "identity:group:create", scopeOfFolderID(folderID)); err != nil {
		return nil, err
	}
	g, err := s.q.CreateGroup(ctx, gen.CreateGroupParams{Name: req.Msg.Name, FolderID: folderID})
	if err != nil {
		return nil, mapWriteErr(err)
	}
	m, err := s.groupMsgWithPath(ctx, g)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.CreateGroupResponse{Group: m}), nil
}

// ResolveGroup resolves a group reference to an id. The reference is one of a
// uuid, a bare name (global group), or `<group>@<folder-path>` (folder-homed).
// The read gate is applied at the resolved group's folder scope, and a read-cap
// denial is existence-hidden as NotFound so a delegated caller cannot learn a
// group exists outside their read scope. The canonical `path` is echoed.
func (s *IdentityServer) ResolveGroup(ctx context.Context, req *connect.Request[identityv1.ResolveGroupRequest]) (*connect.Response[identityv1.ResolveGroupResponse], error) {
	ref := req.Msg.Name
	var grp gen.Group
	if id, perr := uuid.Parse(ref); perr == nil {
		g, err := s.q.GetGroup(ctx, id)
		if err != nil {
			return nil, groupNotFoundOrInternal(err)
		}
		grp = g
	} else if at := strings.LastIndex(ref, "@"); at >= 0 {
		name, folderPath := ref[:at], ref[at+1:]
		folderID, err := resolveFolderIDByPath(ctx, s.q, folderPath)
		if err != nil {
			return nil, groupNotFoundOrInternal(err)
		}
		g, err := s.q.GetGroupByFolderAndName(ctx, gen.GetGroupByFolderAndNameParams{FolderID: pgUUID(folderID), Name: name})
		if err != nil {
			return nil, groupNotFoundOrInternal(err)
		}
		grp = g
	} else {
		g, err := s.q.GetGroupByNameGlobal(ctx, ref)
		if err != nil {
			return nil, groupNotFoundOrInternal(err)
		}
		grp = g
	}
	// Existence-hide a read-cap denial as NotFound (must not reveal a group
	// outside the caller's read scope).
	if err := s.requireCap(ctx, "identity:group:read", scopeOfFolderID(grp.FolderID)); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	m, err := s.groupMsgWithPath(ctx, grp)
	if err != nil {
		return nil, err
	}
	path := m.Name
	if m.FolderPath != "" {
		path = m.Name + "@" + m.FolderPath
	}
	return connect.NewResponse(&identityv1.ResolveGroupResponse{GroupId: grp.ID.String(), Path: path}), nil
}

// ListGroups returns a page of groups the caller may identity:group:read. It is
// visibility-scoped: a global read holder (incl. admin **) sees every group; a
// folder-scoped holder sees only groups homed in folders they can read; a caller
// with no group read caps gets an empty page (not an error).
//
// Pagination uses (name ASC, id ASC) keyset order. For the filtered slow path the
// next-page token is keyed to the SQL page position (last SQL row scanned), not
// the last filtered row, so the cursor advances past invisible groups and
// pagination terminates correctly even when a full page is entirely filtered out.
func (s *IdentityServer) ListGroups(ctx context.Context, req *connect.Request[identityv1.ListGroupsRequest]) (*connect.Response[identityv1.ListGroupsResponse], error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	// Fast path: a global identity:group:read holder (incl. admin **) sees all.
	gcaps, err := s.authz.CapabilitiesOnScope(ctx, u.ID, authz.GlobalScope())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	seesAll := gcaps.Allows("identity:group:read")

	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListGroupsPagedParams{Lim: limit}
	if k != nil {
		params.AfterName = pgtype.Text{String: k.Name, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListGroupsPaged(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Determine the next-page cursor from SQL-page fullness BEFORE filtering.
	// This mirrors the ListPendingApprovals pattern: for filtered paths the token
	// must track the SQL position (last SQL row) so pagination advances past rows
	// the caller cannot see. The fast path (seesAll) also follows this rule for
	// consistency; for the fast path the SQL rows and filtered rows coincide.
	var nextToken string
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		nextToken = encodeNameToken(last.Name, last.ID)
	}

	out := &identityv1.ListGroupsResponse{}
	for i := range rows {
		if !seesAll {
			caps, cerr := s.authz.CapabilitiesOnScope(ctx, u.ID, scopeOfFolderID(rows[i].FolderID))
			if cerr != nil {
				return nil, connect.NewError(connect.CodeInternal, cerr)
			}
			if !caps.Allows("identity:group:read") {
				continue
			}
		}
		out.Groups = append(out.Groups, toGroupMsg(rows[i]))
	}
	out.NextPageToken = nextToken
	return connect.NewResponse(out), nil
}

// AddUserToGroup adds a user as a member of a group (admin only).
func (s *IdentityServer) AddUserToGroup(ctx context.Context, req *connect.Request[identityv1.AddUserToGroupRequest]) (*connect.Response[identityv1.AddUserToGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:add-member", scope); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: gid, MemberUserID: pgUUID(uid)}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.AddUserToGroupResponse{}), nil
}

// AddGroupToGroup nests one group inside another (admin only).
func (s *IdentityServer) AddGroupToGroup(ctx context.Context, req *connect.Request[identityv1.AddGroupToGroupRequest]) (*connect.Response[identityv1.AddGroupToGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:add-member", scope); err != nil {
		return nil, err
	}
	mid, err := uuid.Parse(req.Msg.MemberGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad member_group_id"))
	}
	if err := s.q.AddGroupToGroup(ctx, gen.AddGroupToGroupParams{GroupID: gid, MemberGroupID: pgUUID(mid)}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.AddGroupToGroupResponse{}), nil
}

// RemoveUserFromGroup removes a user from a group (admin only). No-op if absent.
func (s *IdentityServer) RemoveUserFromGroup(ctx context.Context, req *connect.Request[identityv1.RemoveUserFromGroupRequest]) (*connect.Response[identityv1.RemoveUserFromGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:remove-member", scope); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.RemoveUserFromGroup(ctx, gen.RemoveUserFromGroupParams{GroupID: gid, MemberUserID: pgUUID(uid)}); err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&identityv1.RemoveUserFromGroupResponse{}), nil
}

// RemoveGroupFromGroup removes a nested group membership (admin only). No-op if absent.
func (s *IdentityServer) RemoveGroupFromGroup(ctx context.Context, req *connect.Request[identityv1.RemoveGroupFromGroupRequest]) (*connect.Response[identityv1.RemoveGroupFromGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:remove-member", scope); err != nil {
		return nil, err
	}
	mid, err := uuid.Parse(req.Msg.MemberGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad member_group_id"))
	}
	if err := s.q.RemoveGroupFromGroup(ctx, gen.RemoveGroupFromGroupParams{GroupID: gid, MemberGroupID: pgUUID(mid)}); err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&identityv1.RemoveGroupFromGroupResponse{}), nil
}

// ListGroupMembers lists a group's direct member users and member groups with
// keyset pagination over (created_at DESC, id ASC). A single SQL scan covers
// both user-members and group-members; the handler splits the page by which FK
// column is non-null. The next-page token is emitted when the SQL page was full.
func (s *IdentityServer) ListGroupMembers(ctx context.Context, req *connect.Request[identityv1.ListGroupMembersRequest]) (*connect.Response[identityv1.ListGroupMembersResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:read", scope); err != nil {
		return nil, err
	}
	limit := clampPageSize(req.Msg.PageSize)
	k, err := decodePageToken(req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	params := gen.ListGroupMembersPagedParams{GroupID: gid, Lim: limit}
	if k != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *k.Time, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListGroupMembersPaged(ctx, params)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &identityv1.ListGroupMembersResponse{}
	for i := range rows {
		if rows[i].MemberUserID.Valid {
			out.Users = append(out.Users, &identityv1.User{Id: uuidFromPg(rows[i].MemberUserID).String()})
		} else if rows[i].MemberGroupID.Valid {
			out.Groups = append(out.Groups, &identityv1.Group{Id: uuidFromPg(rows[i].MemberGroupID).String()})
		}
	}
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		out.NextPageToken = encodeTimeToken(last.CreatedAt, last.ID)
	}
	return connect.NewResponse(out), nil
}

// DeactivateUser marks a user deactivated, blocking all authenticated RPCs for
// them at token lookup (admin only). Idempotent; unknown ids are a no-op.
func (s *IdentityServer) DeactivateUser(ctx context.Context, req *connect.Request[identityv1.DeactivateUserRequest]) (*connect.Response[identityv1.DeactivateUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:deactivate", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.DeactivateUser(ctx, uid); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// Cascade: revoke the user's active JIT grants so live access ends with the
	// account. Best-effort — the deactivation already stands and the user can no
	// longer authenticate, so a revoke error is logged, not fatal.
	if s.revoker != nil {
		caller, _ := auth.UserFromContext(ctx)
		if _, err := s.revoker.RevokeGrantsForUser(ctx, caller.ID, uid, "user_deactivated"); err != nil {
			slog.Error("deactivation grant-revoke cascade failed", "user_id", uid.String(), "err", err)
		}
	}
	// Force-evict any remaining live sessions (e.g. those resting on a standing
	// binding, which the grant revoke does not cover) so access ends immediately
	// with the account rather than at the next background re-evaluation.
	if s.evictor != nil {
		if _, err := s.evictor.TerminateUser(ctx, uid, "user_deactivated"); err != nil {
			slog.Error("deactivation session-evict cascade failed", "user_id", uid.String(), "err", err)
		}
	}
	return connect.NewResponse(&identityv1.DeactivateUserResponse{}), nil
}

// ReactivateUser clears a user's deactivation (admin only). Idempotent.
func (s *IdentityServer) ReactivateUser(ctx context.Context, req *connect.Request[identityv1.ReactivateUserRequest]) (*connect.Response[identityv1.ReactivateUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:deactivate", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.ReactivateUser(ctx, uid); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&identityv1.ReactivateUserResponse{}), nil
}

// DeleteUser deletes a user; memberships, bindings, and policy subjects cascade
// (admin only). Deleting a non-existent id is a no-op.
func (s *IdentityServer) DeleteUser(ctx context.Context, req *connect.Request[identityv1.DeleteUserRequest]) (*connect.Response[identityv1.DeleteUserResponse], error) {
	if err := s.requireCap(ctx, "identity:user:delete", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := s.q.DeleteUser(ctx, uid); err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&identityv1.DeleteUserResponse{}), nil
}

// DeleteGroup deletes a group; memberships, bindings, and policy subjects cascade.
// Gated by identity:group:delete at the group's folder scope. A non-existent id
// returns NotFound (its governing scope cannot be derived).
func (s *IdentityServer) DeleteGroup(ctx context.Context, req *connect.Request[identityv1.DeleteGroupRequest]) (*connect.Response[identityv1.DeleteGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	scope, err := s.scopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := s.requireCap(ctx, "identity:group:delete", scope); err != nil {
		return nil, err
	}
	if err := s.q.DeleteGroup(ctx, gid); err != nil {
		return nil, mapWriteErr(err)
	}
	return connect.NewResponse(&identityv1.DeleteGroupResponse{}), nil
}
