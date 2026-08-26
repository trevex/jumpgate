// Package access owns the authorization-configuration vertical slice: roles and
// their capabilities, role-rewrite grant edges, standing role bindings, JIT request
// policies and their subjects, plus the admin/self ExplainRole introspection. The
// Service carries the transactional and invariant logic (proto-free) — notably the
// no-escalation subset rule (requireGrantable) and the folder-scoped role
// containment invariant (containedInRoleSubtree); the Handler adapts it to
// ConnectRPC. Role deletion delegates to the accessrequest cascade (roleDeleter) so
// live sessions the role conferred are torn down.
package access

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// roleDeleter runs the transactional DeleteRole cascade (deleting a role plus every
// binding, grant-edge, and policy that references it, and revoking its active grants
// so live sessions are torn down). Backed by *accessrequest.Service; a narrow
// consumer-side seam so the access domain reuses the existing revoke/terminator
// machinery rather than reinventing live-session teardown. May be nil in tests that
// don't exercise deletion.
type roleDeleter interface {
	DeleteRoleCascade(ctx context.Context, actor, roleID uuid.UUID) error
}

// requestReadAuthorizer authorizes display reads for callers who are party to a
// pending access request referencing the entity (the requester or a standing
// approver). It is additive to capability checks: consulted only after a capability
// check denies. Backed by *accessrequest.Service; a nil reqReads disables that path.
type requestReadAuthorizer interface {
	CanReadForRequest(ctx context.Context, caller uuid.UUID, kind accessrequest.ReqEntityKind, id uuid.UUID) (bool, error)
}

// Service is the access domain service. It owns the pool (for the CreateRole
// transaction), the sqlc queries, the role resolver (ExplainRole introspection), the
// authorizer (capability/grantable checks), the role deleter (DeleteRole cascade),
// and the request-read authorizer (GetRoleDisplay decision-context reads).
type Service struct {
	pool     *pgxpool.Pool
	q        *sqlc.Queries
	roles    *authz.RoleResolver
	authz    authz.Authorizer
	deleter  roleDeleter
	reqReads requestReadAuthorizer
}

// NewService constructs the access Service over pool, building its own sqlc queries.
// roles backs ExplainRole; deleter runs the DeleteRole cascade (a nil deleter fails
// DeleteRole closed); reqReads authorizes the request-party path of GetRoleDisplay (a
// nil reqReads disables it, so only the capability grants the read).
func NewService(pool *pgxpool.Pool, roles *authz.RoleResolver, a authz.Authorizer, deleter roleDeleter, reqReads requestReadAuthorizer) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), roles: roles, authz: a, deleter: deleter, reqReads: reqReads}
}

// requireCap denies unless caller holds `capability` at `scope`. It mirrors
// apiguard.Guard.RequireCap so the entangled methods (whose cap checks interleave
// with DB work — role reads gated after the row is loaded, or a no-escalation subset
// check) can gate in place with identical behavior.
func (s *Service) requireCap(ctx context.Context, caller uuid.UUID, capability string, scope authz.Scope) error {
	return apiguard.New(s.authz, s.q).RequireCap(ctx, caller, capability, scope)
}

// requireGrantable enforces the no-escalation subset rule: every capability in
// roleCaps must be subsumed by what caller holds at `scope`.
func (s *Service) requireGrantable(ctx context.Context, caller uuid.UUID, roleCaps []string, scope authz.Scope) error {
	return apiguard.New(s.authz, s.q).RequireGrantable(ctx, caller, roleCaps, scope)
}

// roleCaps loads a role's capability patterns from role_capabilities. NotFound on missing role.
func (s *Service) roleCaps(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	return apiguard.New(s.authz, s.q).RoleCaps(ctx, roleID)
}

// ── small shared helpers (moved verbatim from rpc) ──────────────────────────────

// pgUUID wraps a uuid.UUID as a valid pgtype.UUID.
func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// pgText maps "" to a NULL pgtype.Text, else a valid one.
func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// optUUID parses a possibly-empty UUID string. Empty → (pgtype.UUID{}, false, nil).
func optUUID(s string) (pgtype.UUID, bool, error) {
	if s == "" {
		return pgtype.UUID{}, false, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, false, err
	}
	return pgUUID(id), true, nil
}

// resolveFolderIDByPath walks a DNS-style leaf->root folder path (e.g. "db.prod") to
// a folder id, matching root->leaf. Returns pgx.ErrNoRows if any segment is missing
// so callers can map it to NotFound.
func resolveFolderIDByPath(ctx context.Context, q *sqlc.Queries, path string) (uuid.UUID, error) {
	segs := strings.Split(path, ".")
	var parent pgtype.UUID // NULL = top level
	var folderID uuid.UUID
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := q.FolderByParentName(ctx, sqlc.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
		if err != nil {
			return uuid.Nil, err
		}
		folderID = f.ID
		parent = pgUUID(f.ID)
	}
	return folderID, nil
}

// resolveParentFolderRef resolves an optional folder reference to its id.
// "" → uuid.Nil (root; always browsable, contents are visibility-filtered).
// A valid UUID string → GetFolder lookup (miss → NotFound).
// Else → resolveFolderIDByPath (miss → NotFound). No visibility gate is applied; the
// caller's list operation is itself visibility-filtered.
func resolveParentFolderRef(ctx context.Context, q *sqlc.Queries, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, nil
	}
	if id, err := uuid.Parse(ref); err == nil {
		if _, ferr := q.GetFolder(ctx, id); ferr != nil {
			return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
		return id, nil
	}
	fid, err := resolveFolderIDByPath(ctx, q, ref)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	return fid, nil
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
// Months/Days are folded in using civil-day approximations (30d month, 24h day) so
// admin-configured caps expressed in those units round-trip sensibly.
func intervalToSeconds(iv pgtype.Interval) int64 {
	if !iv.Valid {
		return 0
	}
	const secPerDay = 86400
	return int64(iv.Months)*30*secPerDay + int64(iv.Days)*secPerDay + iv.Microseconds/1_000_000
}

// ── domain result rows (proto-free; the handler maps these to proto) ─────────────

// RoleResult is a single role plus its reconstructed capability patterns and resolved
// folder path ("" for a global/folder-less role).
type RoleResult struct {
	Role       sqlc.Role
	Caps       []string
	FolderPath string
}

// roleResult builds a RoleResult, loading the role's capabilities and resolving its
// folder path when folder-homed. A capability-load or path-lookup error is surfaced
// as Internal (matches the prior roleMsgWithPath behavior).
func (s *Service) roleResult(ctx context.Context, r sqlc.Role) (RoleResult, error) {
	caps, err := apiguard.RoleCapsStrings(ctx, s.q, r.ID)
	if err != nil {
		return RoleResult{}, connect.NewError(connect.CodeInternal, err)
	}
	res := RoleResult{Role: r, Caps: caps}
	if r.FolderID.Valid {
		fp, err := s.q.FolderPath(ctx, apiguard.UUIDFromPg(r.FolderID))
		if err != nil {
			return RoleResult{}, connect.NewError(connect.CodeInternal, err)
		}
		res.FolderPath = fp
	}
	return res, nil
}

// containedInRoleSubtree enforces folder-scoped role containment: if the role is
// folder-scoped, the binding/policy scope (an asset's folder, or a folder directly)
// must lie within the role's folder subtree. Global roles (folder NULL) are
// unrestricted. A folder-scoped role with no scope at all is rejected.
func (s *Service) containedInRoleSubtree(ctx context.Context, roleID uuid.UUID, scopeFolder, scopeAsset pgtype.UUID) error {
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
