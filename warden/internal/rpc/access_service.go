package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// AccessServer implements accessv1connect.AccessServiceHandler: all authorization
// configuration (roles, grants, standing bindings, request policies) plus the
// admin-or-self ExplainRole introspection.
type AccessServer struct {
	q        *sqlc.Queries
	pool     *pgxpool.Pool
	roles    *authz.RoleResolver
	reqReads requestReadAuthorizer
	deleter  roleDeleter
	capGuard
}

// roleDeleter runs the transactional DeleteRole cascade (deleting a role plus every
// binding, grant-edge, and policy that references it, and revoking its active grants
// so live sessions are torn down). Backed by *accessrequest.Service; a narrow seam so
// the handler reuses the existing revoke/terminator machinery rather than reinventing
// live-session teardown. May be nil in tests that don't exercise deletion.
type roleDeleter interface {
	DeleteRoleCascade(ctx context.Context, actor, roleID uuid.UUID) error
}

// NewAccessServer constructs the AccessService implementation. reqReads authorizes
// request-scoped display reads (GetRoleDisplay) for callers who are party to a
// pending access request but lack the read capability; a nil reqReads disables that
// path (only the capability grants the read). deleter runs the DeleteRole cascade.
func NewAccessServer(q *sqlc.Queries, pool *pgxpool.Pool, roles *authz.RoleResolver, a authz.Authorizer, reqReads requestReadAuthorizer, deleter roleDeleter) *AccessServer {
	return &AccessServer{q: q, pool: pool, roles: roles, reqReads: reqReads, deleter: deleter, capGuard: capGuard{guard: apiguard.New(a, q)}}
}

func toAccessRoleMsg(r sqlc.Role, caps []string) *accessv1.Role {
	return &accessv1.Role{
		Id:           r.ID.String(),
		Name:         r.Name,
		Capabilities: caps,
		FolderId:     pgUUIDToString(r.FolderID),
	}
}

// roleMsgWithPath returns the role message with folder_path and capabilities populated.
func (s *AccessServer) roleMsgWithPath(ctx context.Context, r sqlc.Role) (*accessv1.Role, error) {
	caps, err := apiguard.RoleCapsStrings(ctx, s.q, r.ID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	m := toAccessRoleMsg(r, caps)
	if r.FolderID.Valid {
		fp, err := s.q.FolderPath(ctx, apiguard.UUIDFromPg(r.FolderID))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		m.FolderPath = fp
	}
	return m, nil
}

func toAccessRoleGrantMsg(g sqlc.RoleGrant) *accessv1.RoleGrant {
	return &accessv1.RoleGrant{
		Id:           g.ID.String(),
		RoleId:       g.RoleID.String(),
		SourceRoleId: g.SourceRoleID.String(),
		Via:          g.Via,
	}
}

func toRoleBindingMsg(b sqlc.RoleBinding) *accessv1.RoleBinding {
	return &accessv1.RoleBinding{
		Id:             b.ID.String(),
		RoleId:         b.RoleID.String(),
		ScopeFolderId:  pgUUIDToString(b.ScopeFolderID),
		ScopeAssetId:   pgUUIDToString(b.ScopeAssetID),
		SubjectUserId:  pgUUIDToString(b.SubjectUserID),
		SubjectGroupId: pgUUIDToString(b.SubjectGroupID),
	}
}

func toRequestPolicyMsg(r sqlc.RequestPolicy) *accessv1.RequestPolicy {
	return &accessv1.RequestPolicy{
		Id:                 r.ID.String(),
		RoleId:             r.RoleID.String(),
		ScopeFolderId:      pgUUIDToString(r.ScopeFolderID),
		ScopeAssetId:       pgUUIDToString(r.ScopeAssetID),
		RequiredApprovals:  r.RequiredApprovals,
		RequesterRoleId:    pgUUIDToString(r.RequesterRoleID),
		ApproverRoleId:     pgUUIDToString(r.ApproverRoleID),
		MaxDurationSeconds: intervalToSeconds(r.MaxDuration),
		Name:               r.Name.String,
	}
}

// pgText maps "" to a NULL pgtype.Text, else a valid one.
func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// secondsToInterval maps a non-negative seconds count to a pgtype.Interval.
// 0 → invalid (NULL); else a Microseconds-valued interval.
func secondsToInterval(seconds int64) pgtype.Interval {
	if seconds <= 0 {
		return pgtype.Interval{Valid: false}
	}
	return pgtype.Interval{Microseconds: seconds * 1_000_000, Valid: true}
}

// intervalToSeconds maps a pgtype.Interval back to whole seconds; invalid → 0.
// Months/Days are folded in using civil-day approximations (30d month, 24h day)
// so admin-configured caps expressed in those units round-trip sensibly.
func intervalToSeconds(iv pgtype.Interval) int64 {
	if !iv.Valid {
		return 0
	}
	const secPerDay = 86400
	return int64(iv.Months)*30*secPerDay + int64(iv.Days)*secPerDay + iv.Microseconds/1_000_000
}

func toPolicySubjectMsg(s sqlc.RequestPolicySubject) *accessv1.PolicySubject {
	return &accessv1.PolicySubject{
		Id:             s.ID.String(),
		PolicyId:       s.PolicyID.String(),
		Kind:           s.Kind,
		SubjectUserId:  pgUUIDToString(s.SubjectUserID),
		SubjectGroupId: pgUUIDToString(s.SubjectGroupID),
	}
}

// containedInRoleSubtree enforces folder-scoped role containment: if the role is
// folder-scoped, the binding/policy scope (an asset's folder, or a folder directly)
// must lie within the role's folder subtree. Global roles (folder NULL) are
// unrestricted. A folder-scoped role with no scope at all is rejected.
func (s *AccessServer) containedInRoleSubtree(ctx context.Context, roleID uuid.UUID, scopeFolder, scopeAsset pgtype.UUID) error {
	role, err := s.q.GetRole(ctx, roleID)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("bad role_id"))
	}
	if !role.FolderID.Valid {
		return nil // global role: no containment
	}
	var target uuid.UUID
	switch {
	case scopeFolder.Valid:
		target = apiguard.UUIDFromPg(scopeFolder)
	case scopeAsset.Valid:
		a, err := s.q.GetAsset(ctx, apiguard.UUIDFromPg(scopeAsset))
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("bad scope_asset_id"))
		}
		target = a.FolderID
	default:
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("a folder-scoped role requires a scope within its folder subtree"))
	}
	// The role's folder must be an ancestor-or-self of the scope's folder.
	ancestors, err := s.q.FolderAncestorsAndSelf(ctx, target)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	roleFolder := apiguard.UUIDFromPg(role.FolderID)
	for _, a := range ancestors {
		if a == roleFolder {
			return nil
		}
	}
	return connect.NewError(connect.CodeFailedPrecondition, errors.New("role is scoped to a folder and can only be bound within its subtree"))
}
