package identity

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Handler adapts the identity Service to the generated IdentityServiceHandler
// interface: it extracts the caller from context, validates + parses proto, applies
// the capability gate for gate-first methods (entangled cap/visibility checks stay
// in the service, which takes the caller explicitly), calls one service method, and
// maps the domain result back to proto.
type Handler struct {
	svc   *Service
	guard apiguard.Guard
}

// NewHandler constructs the identity transport Handler over svc and guard.
func NewHandler(svc *Service, guard apiguard.Guard) *Handler {
	return &Handler{svc: svc, guard: guard}
}

// caller extracts the authenticated user's id from ctx. In real requests the auth
// interceptor guarantees a user; an in-process caller without one is Unauthenticated.
func caller(ctx context.Context) (uuid.UUID, error) {
	u, ok := auth.UserFromContext(ctx)
	if !ok {
		return uuid.Nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return u.ID, nil
}

// ── proto mapping ────────────────────────────────────────────────────────────

// pgUUIDToString renders a nullable pgtype.UUID as a string ("" for NULL).
func pgUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func toUserMsg(u sqlc.User) *identityv1.User {
	return &identityv1.User{Id: u.ID.String(), Email: u.Email, DisplayName: u.DisplayName, Active: !u.DeactivatedAt.Valid}
}

// groupMsg renders a GroupResult as an identity Group with its folder path.
func groupMsg(res GroupResult) *identityv1.Group {
	return &identityv1.Group{
		Id:         res.Group.ID.String(),
		Name:       res.Group.Name,
		FolderId:   pgUUIDToString(res.Group.FolderID),
		FolderPath: res.FolderPath,
	}
}

// ── users ────────────────────────────────────────────────────────────────────

// CreateUser gates on identity:user:create (global) then delegates to the service.
func (h *Handler) CreateUser(ctx context.Context, req *connect.Request[identityv1.CreateUserRequest]) (*connect.Response[identityv1.CreateUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:create", authz.GlobalScope()); err != nil {
		return nil, err
	}
	u, err := h.svc.CreateUser(ctx, req.Msg.Email, req.Msg.DisplayName, req.Msg.Password)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.CreateUserResponse{User: toUserMsg(u)}), nil
}

// GetUser returns a user by id (identity:user:read, global). Unknown ids are NotFound.
func (h *Handler) GetUser(ctx context.Context, req *connect.Request[identityv1.GetUserRequest]) (*connect.Response[identityv1.GetUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	u, err := h.svc.GetUser(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.GetUserResponse{User: toUserMsg(u)}), nil
}

// GetUserDisplay returns minimal display info for a user id. It is a universal
// directory read: any authenticated caller may call it, with no capability check, so
// the console can render user names/avatars. A missing or malformed id is NotFound; a
// deactivated user is still returned (display metadata, not an authz decision).
func (h *Handler) GetUserDisplay(ctx context.Context, req *connect.Request[identityv1.GetUserDisplayRequest]) (*connect.Response[identityv1.GetUserDisplayResponse], error) {
	if _, err := caller(ctx); err != nil {
		return nil, err
	}
	u, err := h.svc.GetUserDisplay(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.GetUserDisplayResponse{User: &identityv1.UserDisplay{
		Id: u.ID.String(), DisplayName: u.DisplayName, Email: u.Email,
	}}), nil
}

// ResolveUser resolves a user email to an id (identity:user:read, global). Unknown
// emails are NotFound.
func (h *Handler) ResolveUser(ctx context.Context, req *connect.Request[identityv1.ResolveUserRequest]) (*connect.Response[identityv1.ResolveUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:read", authz.GlobalScope()); err != nil {
		return nil, err
	}
	u, err := h.svc.ResolveUser(ctx, req.Msg.Email)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.ResolveUserResponse{UserId: u.ID.String()}), nil
}

// ListUsers returns a page of users. User display info is a UNIVERSAL DIRECTORY READ:
// any authenticated caller may list it (the same rule as GetUserDisplay). It backs
// the subject/member pickers, request/approval attribution, and avatars, so a
// folder-delegated admin must be able to browse users WITHOUT a global
// identity:user:read. Management operations remain capability-gated; only the
// display-safe read is open.
func (h *Handler) ListUsers(ctx context.Context, req *connect.Request[identityv1.ListUsersRequest]) (*connect.Response[identityv1.ListUsersResponse], error) {
	if _, err := caller(ctx); err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListUsers(ctx, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &identityv1.ListUsersResponse{NextPageToken: next}
	for i := range rows {
		out.Users = append(out.Users, toUserMsg(rows[i]))
	}
	return connect.NewResponse(out), nil
}

// DeactivateUser marks a user deactivated (global), then cascades grant revoke +
// session eviction. Idempotent; unknown ids are a no-op.
func (h *Handler) DeactivateUser(ctx context.Context, req *connect.Request[identityv1.DeactivateUserRequest]) (*connect.Response[identityv1.DeactivateUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:deactivate", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := h.svc.DeactivateUser(ctx, c, uid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.DeactivateUserResponse{}), nil
}

// ReactivateUser clears a user's deactivation (global). Idempotent.
func (h *Handler) ReactivateUser(ctx context.Context, req *connect.Request[identityv1.ReactivateUserRequest]) (*connect.Response[identityv1.ReactivateUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:deactivate", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := h.svc.ReactivateUser(ctx, uid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.ReactivateUserResponse{}), nil
}

// DeleteUser deletes a user (global); memberships, bindings, and policy subjects
// cascade. Deleting a non-existent id is a no-op.
func (h *Handler) DeleteUser(ctx context.Context, req *connect.Request[identityv1.DeleteUserRequest]) (*connect.Response[identityv1.DeleteUserResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:user:delete", authz.GlobalScope()); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := h.svc.DeleteUser(ctx, uid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.DeleteUserResponse{}), nil
}

// ── groups ───────────────────────────────────────────────────────────────────

// CreateGroup gates on identity:group:create at the group's folder scope, then
// delegates to the service.
func (h *Handler) CreateGroup(ctx context.Context, req *connect.Request[identityv1.CreateGroupRequest]) (*connect.Response[identityv1.CreateGroupResponse], error) {
	folderID, _, err := optUUID(req.Msg.FolderId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad folder_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:create", apiguard.ScopeOfFolderID(folderID)); err != nil {
		return nil, err
	}
	res, err := h.svc.CreateGroup(ctx, folderID, req.Msg.Name)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.CreateGroupResponse{Group: groupMsg(res)}), nil
}

// ResolveGroup maps a uuid | bare name | <group>@<folder-path> to a group id
// (existence-hidden), echoing the canonical addressable path.
func (h *Handler) ResolveGroup(ctx context.Context, req *connect.Request[identityv1.ResolveGroupRequest]) (*connect.Response[identityv1.ResolveGroupResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.svc.ResolveGroup(ctx, c, req.Msg.Name)
	if err != nil {
		return nil, err
	}
	path := res.Group.Name
	if res.FolderPath != "" {
		path = res.Group.Name + "@" + res.FolderPath
	}
	return connect.NewResponse(&identityv1.ResolveGroupResponse{GroupId: res.Group.ID.String(), Path: path}), nil
}

// ListGroups returns the caller's visible group page under the requested parent.
func (h *Handler) ListGroups(ctx context.Context, req *connect.Request[identityv1.ListGroupsRequest]) (*connect.Response[identityv1.ListGroupsResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListGroups(ctx, c, req.Msg.Parent, req.Msg.Cascade, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &identityv1.ListGroupsResponse{NextPageToken: next}
	for _, r := range rows {
		out.Groups = append(out.Groups, groupMsg(GroupResult(r)))
	}
	return connect.NewResponse(out), nil
}

// GetGroupAccess returns the caller's management capabilities on one group.
func (h *Handler) GetGroupAccess(ctx context.Context, req *connect.Request[identityv1.GetGroupAccessRequest]) (*connect.Response[identityv1.GetGroupAccessResponse], error) {
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	caps, err := h.svc.GetGroupAccess(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.GetGroupAccessResponse{Capabilities: caps}), nil
}

// AddUserToGroup adds a user to a group, gated by identity:group:add-member at the
// group's folder scope.
func (h *Handler) AddUserToGroup(ctx context.Context, req *connect.Request[identityv1.AddUserToGroupRequest]) (*connect.Response[identityv1.AddUserToGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:add-member", scope); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := h.svc.AddUserToGroup(ctx, gid, uid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.AddUserToGroupResponse{}), nil
}

// AddGroupToGroup nests one group inside another, gated by identity:group:add-member
// at the parent group's folder scope. The acyclicity invariant lives in the service.
func (h *Handler) AddGroupToGroup(ctx context.Context, req *connect.Request[identityv1.AddGroupToGroupRequest]) (*connect.Response[identityv1.AddGroupToGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:add-member", scope); err != nil {
		return nil, err
	}
	mid, err := uuid.Parse(req.Msg.MemberGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad member_group_id"))
	}
	if err := h.svc.AddGroupToGroup(ctx, gid, mid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.AddGroupToGroupResponse{}), nil
}

// RemoveUserFromGroup removes a user from a group, gated by
// identity:group:remove-member at the group's folder scope. No-op if absent.
func (h *Handler) RemoveUserFromGroup(ctx context.Context, req *connect.Request[identityv1.RemoveUserFromGroupRequest]) (*connect.Response[identityv1.RemoveUserFromGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:remove-member", scope); err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(req.Msg.UserId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad user_id"))
	}
	if err := h.svc.RemoveUserFromGroup(ctx, gid, uid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.RemoveUserFromGroupResponse{}), nil
}

// RemoveGroupFromGroup removes a nested group membership, gated by
// identity:group:remove-member at the parent group's folder scope. No-op if absent.
func (h *Handler) RemoveGroupFromGroup(ctx context.Context, req *connect.Request[identityv1.RemoveGroupFromGroupRequest]) (*connect.Response[identityv1.RemoveGroupFromGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:remove-member", scope); err != nil {
		return nil, err
	}
	mid, err := uuid.Parse(req.Msg.MemberGroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad member_group_id"))
	}
	if err := h.svc.RemoveGroupFromGroup(ctx, gid, mid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.RemoveGroupFromGroupResponse{}), nil
}

// ListGroupMembers lists a group's direct member users and member groups, gated by
// identity:group:read at the group's folder scope.
func (h *Handler) ListGroupMembers(ctx context.Context, req *connect.Request[identityv1.ListGroupMembersRequest]) (*connect.Response[identityv1.ListGroupMembersResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:read", scope); err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListGroupMembers(ctx, gid, req.Msg.PageSize, req.Msg.PageToken)
	if err != nil {
		return nil, err
	}
	out := &identityv1.ListGroupMembersResponse{NextPageToken: next}
	for i := range rows {
		if rows[i].MemberUserID.Valid {
			out.Users = append(out.Users, &identityv1.User{Id: apiguard.UUIDFromPg(rows[i].MemberUserID).String()})
		} else if rows[i].MemberGroupID.Valid {
			out.Groups = append(out.Groups, &identityv1.Group{Id: apiguard.UUIDFromPg(rows[i].MemberGroupID).String()})
		}
	}
	return connect.NewResponse(out), nil
}

// DeleteGroup deletes a group, gated by identity:group:delete at the group's folder
// scope. A non-existent id returns NotFound (its governing scope cannot be derived).
func (h *Handler) DeleteGroup(ctx context.Context, req *connect.Request[identityv1.DeleteGroupRequest]) (*connect.Response[identityv1.DeleteGroupResponse], error) {
	gid, err := uuid.Parse(req.Msg.GroupId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad group_id"))
	}
	c, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	scope, err := h.guard.ScopeOfGroup(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.guard.RequireCap(ctx, c, "identity:group:delete", scope); err != nil {
		return nil, err
	}
	if err := h.svc.DeleteGroup(ctx, gid); err != nil {
		return nil, err
	}
	return connect.NewResponse(&identityv1.DeleteGroupResponse{}), nil
}
