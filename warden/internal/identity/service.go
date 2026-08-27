// Package identity owns the identity domain vertical slice: users (lifecycle +
// directory reads), groups (governance + membership DAG), and the resolve/display
// reads that back the console pickers. The Service carries the transactional and
// invariant logic (proto-free); the Handler adapts it to ConnectRPC. Authorization
// config (roles/bindings) lives in the access domain; identity only reads group
// visibility and capability scopes from the authorizer.
package identity

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/apipage"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// grantRevoker revokes a user's active JIT grants. Satisfied by
// *accessrequest.Service; declared here as a narrow consumer-side interface so the
// identity Service depends only on the capability it needs. A nil revoker disables
// the deactivation grant-revoke cascade.
type grantRevoker interface {
	RevokeGrantsForUser(ctx context.Context, actor, userID uuid.UUID, reason string) (int, error)
}

// sessionEvictor force-terminates all of a user's live sessions. Satisfied by
// *dataplane.Terminator; a narrow consumer-side interface. A nil evictor disables
// the deactivation session-evict cascade.
type sessionEvictor interface {
	TerminateUser(ctx context.Context, userID uuid.UUID, reason string) (int, error)
}

// Service is the identity domain service. It owns the pool (for the CreateUser
// transaction and the group-nesting cycle guard), the sqlc queries, the grant
// revoker + session evictor (deactivation cascade), and the authorizer (group
// visibility + capability scopes).
type Service struct {
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	guard   apiguard.Guard
	revoker grantRevoker
	evictor sessionEvictor
	authz   *authz.Authorizer
}

// NewService constructs the identity Service over pool, building its own sqlc
// queries. revoker cascades JIT grant revocation on DeactivateUser and evictor
// force-evicts the user's remaining live sessions; either may be nil in tests that
// don't exercise deactivation teardown.
func NewService(pool *pgxpool.Pool, revoker grantRevoker, evictor sessionEvictor, a *authz.Authorizer) *Service {
	q := sqlc.New(pool)
	return &Service{pool: pool, q: q, guard: apiguard.New(a, q), revoker: revoker, evictor: evictor, authz: a}
}

// ── small shared helpers (moved verbatim from rpc) ──────────────────────────────

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
		parent = pgconv.UUID(f.ID)
	}
	return folderID, nil
}

// resolveParentFolderRef resolves an optional folder reference to its id.
// "" → uuid.Nil (root; always browsable, contents are visibility-filtered).
// A valid UUID string → GetFolder lookup (miss → NotFound).
// Else → resolveFolderIDByPath (miss → NotFound). No visibility gate is applied;
// the caller's list operation is itself visibility-filtered.
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

// ── domain result rows (proto-free; the handler maps these to proto) ─────────────

// GroupResult is a single group plus its resolved folder path ("" for a global group).
type GroupResult struct {
	Group      sqlc.Group
	FolderPath string
}

// GroupRow is a browse/list group row plus its resolved folder path ("" for global).
type GroupRow struct {
	Group      sqlc.Group
	FolderPath string
}

// groupResult builds a GroupResult, resolving the folder path when the group is
// folder-homed. A path lookup error is surfaced as Internal (matches the prior
// groupMsgWithPath behavior).
func (s *Service) groupResult(ctx context.Context, g sqlc.Group) (GroupResult, error) {
	res := GroupResult{Group: g}
	if g.FolderID.Valid {
		fp, err := s.q.FolderPath(ctx, apiguard.UUIDFromPg(g.FolderID))
		if err != nil {
			return GroupResult{}, connect.NewError(connect.CodeInternal, err)
		}
		res.FolderPath = fp
	}
	return res, nil
}

// ── users ────────────────────────────────────────────────────────────────────

// CreateUser creates a local user. The password hash, the user row, and the
// password write are committed in one transaction so a password-write failure
// leaves NO user row (this closes the prior non-atomic gap). A duplicate email is
// AlreadyExists; any other write failure is Internal.
func (s *Service) CreateUser(ctx context.Context, email, displayName, password string) (sqlc.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeInternal, err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeInternal, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.q.WithTx(tx)

	u, err := qtx.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: displayName})
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeAlreadyExists, errors.New("email already exists"))
	}
	if err := qtx.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeInternal, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeInternal, err)
	}
	return u, nil
}

// GetUser returns a user by id. A malformed id or an unknown id is NotFound.
func (s *Service) GetUser(ctx context.Context, idStr string) (sqlc.User, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return u, nil
}

// GetUserDisplay returns a user row for the universal directory-read display path.
// A malformed or missing id is NotFound. A deactivated user is still returned —
// this is display metadata, not an authorization decision.
func (s *Service) GetUserDisplay(ctx context.Context, idStr string) (sqlc.User, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return sqlc.User{}, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return u, nil
}

// ResolveUser resolves a user email to a row. An unknown email is NotFound.
func (s *Service) ResolveUser(ctx context.Context, email string) (sqlc.User, error) {
	u, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.User{}, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return sqlc.User{}, connect.NewError(connect.CodeInternal, err)
	}
	return u, nil
}

// ListUsers returns a page of users ordered by (email ASC, id ASC) and an opaque
// next-page token (emitted only when the page was filled).
func (s *Service) ListUsers(ctx context.Context, pageSize int32, pageToken string) ([]sqlc.User, string, error) {
	limit := apipage.ClampPageSize(pageSize)
	k, err := apipage.DecodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	params := sqlc.ListUsersParams{Lim: limit}
	if k != nil {
		params.AfterEmail = pgtype.Text{String: k.Name, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: k.ID, Valid: true}
	}
	rows, err := s.q.ListUsers(ctx, params)
	if err != nil {
		return nil, "", connect.NewError(connect.CodeInternal, err)
	}
	// Emit a token only when the page was filled; an exact multiple of page_size
	// costs one extra empty trailing page (standard strict-last-page tradeoff).
	// The sort key is email.
	next := ""
	if len(rows) == int(limit) {
		last := rows[len(rows)-1]
		next = apipage.EncodeNameToken(last.Email, last.ID)
	}
	return rows, next, nil
}

// DeactivateUser marks a user deactivated (idempotent; unknown ids are a no-op at
// the SQL level), then best-effort cascades: revoke the user's active JIT grants and
// force-evict any remaining live sessions. actor is the deactivating caller (the
// revoke actor). Both cascade steps are best-effort — the deactivation already
// stands and the user can no longer authenticate, so a cascade error is logged, not
// fatal.
func (s *Service) DeactivateUser(ctx context.Context, actor, uid uuid.UUID) error {
	if err := s.q.DeactivateUser(ctx, uid); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	// Cascade: revoke the user's active JIT grants so live access ends with the
	// account. Best-effort — see method doc.
	if s.revoker != nil {
		if _, err := s.revoker.RevokeGrantsForUser(ctx, actor, uid, "user_deactivated"); err != nil {
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
	return nil
}

// ReactivateUser clears a user's deactivation. Idempotent.
func (s *Service) ReactivateUser(ctx context.Context, uid uuid.UUID) error {
	if err := s.q.ReactivateUser(ctx, uid); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	return nil
}

// DeleteUser deletes a user; memberships, bindings, and policy subjects cascade.
// Deleting a non-existent id is a no-op.
func (s *Service) DeleteUser(ctx context.Context, uid uuid.UUID) error {
	if err := s.q.DeleteUser(ctx, uid); err != nil {
		return apierr.MapWrite(err)
	}
	return nil
}
