package accessrequest

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ReqEntityKind selects which entity a request-party read is about.
type ReqEntityKind int

// The entity kinds a request-party read may target.
const (
	ReqEntityAsset ReqEntityKind = iota // an asset referenced by a pending request
	ReqEntityRole                       // a role referenced by a pending request
)

// party is the normalised shape of a pending request row: the two generated
// by-entity row types carry identical fields, folded here into one.
type party struct {
	requester uuid.UUID
	role      uuid.UUID
	asset     uuid.UUID
}

// ListMyRequests returns the caller's own requests, newest first.
func (s *Service) ListMyRequests(ctx context.Context, requester uuid.UUID) ([]Request, error) {
	q := sqlc.New(s.pool)
	rows, err := q.ListAccessRequestsByRequester(ctx, requester)
	if err != nil {
		return nil, fmt.Errorf("list my requests: %w", err)
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		count, err := q.CountApprovals(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("count approvals: %w", err)
		}
		grantID := s.grantIDFor(ctx, q, r)
		out = append(out, toRequest(r, int(count), grantID))
	}
	return out, nil
}

// ListPendingApprovals returns pending requests the caller may approve (an
// eligible approver, excluding the caller's own requests). The pending set is
// small; filter in Go via IsApprover for correctness over cleverness.
func (s *Service) ListPendingApprovals(ctx context.Context, caller uuid.UUID) ([]Request, error) {
	return s.approvablePending(ctx, caller, nil)
}

// approvablePending resolves, in ONE set-based query, the pending access requests
// the caller may approve (with their approve-count). A candidate is included when
// the caller is neither its requester nor deactivated AND, for the request's
// EFFECTIVE policy (most-specific of asset / folder-ancestor / global), the caller
// is an explicit `approver` subject (direct or via a nested group) OR holds the
// policy's approver_role STANDING on the asset. The standing arm reuses
// authz_held_standing, so governance cannot drift from HoldsRoleStanding. Results
// are ordered created_at DESC, id.
//
// RESTRICT CONTRACT: pass nil for "all" (SQL NULL). An EMPTY non-nil slice encodes
// as `'{}'` → zero rows, so callers must never pass []uuid.UUID{} to mean "all".
func (s *Service) approvablePending(ctx context.Context, caller uuid.UUID, restrict []uuid.UUID) ([]Request, error) {
	rows, err := s.q.ApprovablePending(ctx, sqlc.ApprovablePendingParams{Caller: caller, Restrict: restrict})
	if err != nil {
		return nil, fmt.Errorf("approvable pending: %w", err)
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRequest(sqlc.AccessRequest{
			ID: r.ID, RequesterUserID: r.RequesterUserID, RoleID: r.RoleID, AssetID: r.AssetID,
			Reason: r.Reason, RequiredApprovals: r.RequiredApprovals, Status: r.Status,
			CreatedAt: r.CreatedAt.Time, ResolvedAt: r.ResolvedAt,
		}, int(r.Approvals.Int64), uuid.Nil))
	}
	return out, nil
}

// CanReadForRequest reports whether caller may read the given entity because they
// are party to a PENDING access request that references it: the requester, or a
// standing approver (governance is standing-only; a JIT grant never confers it).
// Additive to capability checks — callers consult it only after a cap check
// denies. A deactivated caller is never party (IsApprover already excludes them;
// the requester branch checks activity explicitly).
func (s *Service) CanReadForRequest(ctx context.Context, caller uuid.UUID, kind ReqEntityKind, id uuid.UUID) (bool, error) {
	q := sqlc.New(s.pool)

	var parties []party
	switch kind {
	case ReqEntityAsset:
		rows, err := q.ListPendingRequestsByAsset(ctx, id)
		if err != nil {
			return false, fmt.Errorf("pending by asset: %w", err)
		}
		for _, r := range rows {
			parties = append(parties, party{requester: r.RequesterUserID, role: r.RoleID, asset: r.AssetID})
		}
	case ReqEntityRole:
		rows, err := q.ListPendingRequestsByRole(ctx, id)
		if err != nil {
			return false, fmt.Errorf("pending by role: %w", err)
		}
		for _, r := range rows {
			parties = append(parties, party{requester: r.RequesterUserID, role: r.RoleID, asset: r.AssetID})
		}
	default:
		return false, nil
	}

	for _, p := range parties {
		if p.requester == caller {
			// The requester is party — but a deactivated user is party to nothing.
			active, err := q.IsUserActive(ctx, caller)
			if err != nil {
				return false, fmt.Errorf("is user active: %w", err)
			}
			if active {
				return true, nil
			}
			continue
		}
		// Standing approver of this request's (role, asset). IsApprover is
		// standing-only and already excludes deactivated users.
		ok, err := s.resolver.IsApprover(ctx, caller, p.role, p.asset)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// CanReviewGrant reports whether caller may review the sessions/recordings of
// grantID: caller is the grant's subject, OR a potential approver of the grant's
// originating request (the same standing approver-eligibility as the
// pending-approvals inbox, generalized past pending). Additive to capability
// checks — callers consult it only after a cap check denies. Fails closed: an
// unknown grant yields false, not an error swallowed to true.
func (s *Service) CanReviewGrant(ctx context.Context, caller, grantID uuid.UUID) (bool, error) {
	g, err := sqlc.New(s.pool).GetGrant(ctx, grantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("get grant: %w", err)
	}
	if g.SubjectUserID == caller {
		return true, nil
	}
	// Standing approver of the grant's originating (role, asset). IsApprover is
	// standing-only (a JIT grant never confers approver eligibility) and already
	// excludes deactivated users.
	return s.resolver.IsApprover(ctx, caller, g.RoleID, g.ScopeAssetID)
}

// grantIDFor returns the grant id for a granted request, or uuid.Nil.
func (s *Service) grantIDFor(ctx context.Context, q *sqlc.Queries, r sqlc.AccessRequest) uuid.UUID {
	if r.Status != "granted" {
		return uuid.Nil
	}
	gr, err := q.GetGrantByRequest(ctx, r.ID)
	if err != nil {
		return uuid.Nil
	}
	return gr.ID
}

// ListMyRequestsPaged returns the caller's own requests with keyset pagination
// on (created_at DESC, id ASC).
func (s *Service) ListMyRequestsPaged(ctx context.Context, requester uuid.UUID, page PageParams) ([]Request, error) {
	q := sqlc.New(s.pool)
	params := sqlc.ListAccessRequestsByRequesterPagedParams{
		RequesterUserID: requester,
		Lim:             page.Limit,
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := q.ListAccessRequestsByRequesterPaged(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list my requests paged: %w", err)
	}
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		count, err := q.CountApprovals(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("count approvals: %w", err)
		}
		grantID := s.grantIDFor(ctx, q, r)
		out = append(out, toRequest(r, int(count), grantID))
	}
	return out, nil
}

// ListPendingApprovalsPaged returns pending requests the caller may approve,
// with keyset pagination on the underlying pending-requests scan. The Go-side
// IsApprover filter runs after the SQL limit, so pages may be shorter than
// page_size when many pending requests belong to other policies.
//
// The returned *PageCursor is non-nil when the SQL page was full (len(sqlRows)
// == limit) and carries the (created_at, id) of the LAST SQL ROW SCANNED.
// Callers must base the next-page token on this cursor — not on the last
// filtered row — so the cursor tracks SQL position even when all rows on a
// page were filtered out.
func (s *Service) ListPendingApprovalsPaged(ctx context.Context, caller uuid.UUID, page PageParams) ([]Request, *PageCursor, error) {
	q := sqlc.New(s.pool)
	params := sqlc.ListPendingRequestsPagedParams{Lim: page.Limit}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := q.ListPendingRequestsPaged(ctx, params)
	if err != nil {
		return nil, nil, fmt.Errorf("list pending approvals paged: %w", err)
	}

	// Determine SQL-page cursor before filtering: emit a token whenever the SQL
	// page was full so the next call resumes past everything already examined,
	// even if every row on this page was filtered out for this caller.
	var next *PageCursor
	if len(rows) == int(page.Limit) {
		last := rows[len(rows)-1]
		next = &PageCursor{Ts: last.CreatedAt, ID: last.ID}
	}
	if len(rows) == 0 {
		return make([]Request, 0), next, nil
	}

	// Approvability is resolved set-based over just this page's request ids (one
	// query), preserving the page order (created_at DESC, id) and the SQL-page cursor.
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	out, err := s.approvablePending(ctx, caller, ids)
	if err != nil {
		return nil, nil, err
	}
	return out, next, nil
}

// ListReviewableGrantsPaged returns grants the caller may review — subject OR
// standing potential approver of the grant's originating (role, asset) — with
// keyset pagination on (granted_at DESC, id ASC). It fetches an unfiltered SQL page
// (active_only=false, so past/revoked grants remain reviewable) then filters in Go;
// the returned cursor tracks the LAST SQL ROW scanned (not the last kept row) so a
// full SQL page always emits a next-cursor, even if every row was filtered out. The
// per-row filter IS the authz for this caller-scoped list (no capability gate).
func (s *Service) ListReviewableGrantsPaged(ctx context.Context, caller uuid.UUID, page PageParams) ([]Grant, *PageCursor, error) {
	params := sqlc.ListGrantsFilteredPagedParams{
		ActiveOnly: false, // include revoked/expired/past grants
		Lim:        page.Limit,
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsFilteredPaged(ctx, params)
	if err != nil {
		return nil, nil, fmt.Errorf("list reviewable grants paged: %w", err)
	}

	// Determine the SQL-page cursor before filtering: emit a token whenever the
	// SQL page was full so the next call resumes past everything already examined,
	// even if every row on this page was filtered out for this caller.
	var next *PageCursor
	if len(rows) == int(page.Limit) {
		last := rows[len(rows)-1]
		next = &PageCursor{Ts: last.GrantedAt, ID: last.ID}
	}

	if len(rows) == 0 {
		return make([]Grant, 0), next, nil
	}

	// Reviewability is resolved set-based over just this page's grant ids (one query),
	// preserving the page order (granted_at DESC, id) and the SQL-page cursor.
	ids := make([]uuid.UUID, len(rows))
	for i, g := range rows {
		ids[i] = g.ID
	}
	out, err := s.reviewableGrants(ctx, caller, ids)
	if err != nil {
		return nil, nil, err
	}
	return out, next, nil
}

// reviewableGrants resolves, in ONE set-based query, the grants the caller may
// review (the set form of CanReviewGrant). A grant is reviewable when the caller is
// its subject OR (active AND, for the grant's (role, asset) EFFECTIVE policy, an
// explicit approver subject or holds the approver_role STANDING on the asset). The
// subject arm intentionally has no active-user check, matching CanReviewGrant; the
// standing arm reuses authz_held_standing (single-sourced with HoldsRoleStanding).
// restrict limits to those grant ids (nil = SQL NULL = all). Ordered granted_at
// DESC, id.
func (s *Service) reviewableGrants(ctx context.Context, caller uuid.UUID, restrict []uuid.UUID) ([]Grant, error) {
	rows, err := s.q.ReviewableGrants(ctx, sqlc.ReviewableGrantsParams{
		Caller:   pgtype.UUID{Bytes: caller, Valid: true},
		Restrict: restrict,
	})
	if err != nil {
		return nil, fmt.Errorf("reviewable grants: %w", err)
	}
	out := make([]Grant, 0, len(rows))
	for _, g := range rows {
		out = append(out, toGrant(sqlc.AccessGrant{
			ID: g.ID, RoleID: g.RoleID, ScopeAssetID: g.ScopeAssetID, SubjectUserID: g.SubjectUserID,
			GrantedAt: g.GrantedAt.Time, ExpiresAt: g.ExpiresAt.Time, RevokedAt: g.RevokedAt, RevokedReason: g.RevokedReason,
		}))
	}
	return out, nil
}
