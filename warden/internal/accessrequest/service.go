// Package accessrequest implements the JIT access-request workflow: request a
// role on an asset, approve/deny/cancel a pending request, and mint time-boxed
// access_grants when a request reaches its required-approval threshold.
//
// CONCURRENCY: state transitions take a row lock on the access_request
// (GetAccessRequestForUpdate, FOR UPDATE) and count approvals inside the same
// tx, so two concurrent approvals cannot both cross the threshold and mint two
// grants. UNIQUE(request_id) on access_grants is the backstop; UNIQUE(request_id,
// approver_user_id) blocks double-voting.
//
// AUDIT: audit events are enqueued into the audit_outbox WITHIN the domain tx
// via audit.Logger.Enqueue (a plain insert on the caller's tx-bound querier), so
// each event becomes durable ATOMICALLY with the state change it records — either
// both commit or neither does. An enqueue failure rolls back the domain action
// (the RPC fails), because a durable action with no audit entry is not acceptable.
// A background drainer (audit.Logger.RunDrainer/DrainOnce) later moves outbox rows
// into the hash-linked, tamper-evident audit_log in seq order. Terminator
// notification (live-session teardown) stays POST-COMMIT: it must not fire for a
// change that then rolls back.
package accessrequest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// pgUniqueViolation is the SQLSTATE for a unique-constraint violation.
const pgUniqueViolation = "23505"

// Sentinel errors the RPC handler maps to Connect codes.
var (
	ErrNotEligible      = errors.New("not eligible to request this role")    // → NotFound (existence-hiding)
	ErrNotRequestable   = errors.New("role is not JIT-requestable on asset") // → FailedPrecondition
	ErrAlreadyActive    = errors.New("role already active on asset")         // → FailedPrecondition
	ErrDuplicatePending = errors.New("a pending request already exists")     // → AlreadyExists
	ErrNotPending       = errors.New("request is not pending")               // → FailedPrecondition
	ErrNotApprover      = errors.New("not an approver for this request")     // → PermissionDenied
	ErrSelfApprove      = errors.New("cannot approve your own request")      // → PermissionDenied
	ErrAlreadyVoted     = errors.New("already voted on this request")        // → AlreadyExists
	ErrNotRequester     = errors.New("not the requester")                    // → PermissionDenied
	ErrGrantNotFound    = errors.New("grant not found")                      // → NotFound
	ErrRevokeForbidden  = errors.New("not permitted to revoke this grant")   // → PermissionDenied
	ErrGrantInactive    = errors.New("grant is already inactive")            // → FailedPrecondition
)

// Request is the DTO returned to the transport layer.
type Request struct {
	ID                uuid.UUID
	RequesterID       uuid.UUID
	RoleID            uuid.UUID
	AssetID           uuid.UUID
	Status            string
	RequiredApprovals int
	ApprovalsSoFar    int
	Reason            string
	CreatedAt         time.Time
	ResolvedAt        time.Time // zero when unresolved
	GrantID           uuid.UUID // uuid.Nil when no grant minted
}

// Grant is the DTO for an access_grant returned to the transport layer.
type Grant struct {
	ID            uuid.UUID
	RoleID        uuid.UUID
	AssetID       uuid.UUID
	SubjectUserID uuid.UUID
	GrantedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time // zero when not revoked
	RevokedReason string
	Active        bool // revoked_at IS NULL AND expires_at > now()
}

// Service is the JIT access-request domain service.
type Service struct {
	pool       *pgxpool.Pool
	q          *sqlc.Queries
	audit      *audit.Logger
	resolver   *approvals.Resolver
	roles      *authz.RoleResolver
	terminator GrantTerminator
	maxTTL     time.Duration
}

// NewService constructs the access-request Service. A nil terminator defaults to
// NoopTerminator; production wires the real dataplane.Terminator (M4a), which tears
// down live sessions on revocation via closure re-eval + LISTEN/NOTIFY.
func NewService(pool *pgxpool.Pool, auditLog *audit.Logger, resolver *approvals.Resolver, roles *authz.RoleResolver, terminator GrantTerminator, maxTTL time.Duration) *Service {
	if maxTTL <= 0 {
		maxTTL = 8 * time.Hour
	}
	if terminator == nil {
		terminator = NoopTerminator{}
	}
	return &Service{pool: pool, q: sqlc.New(pool), audit: auditLog, resolver: resolver, roles: roles, terminator: terminator, maxTTL: maxTTL}
}

// intervalToDuration converts a pgtype.Interval to a time.Duration, folding
// Months/Days with civil-day approximations (30d month, 24h day) so admin caps
// expressed in those units are honored. Invalid/zero → (0, false).
func intervalToDuration(iv pgtype.Interval) (time.Duration, bool) {
	if !iv.Valid {
		return 0, false
	}
	const day = 24 * time.Hour
	d := time.Duration(iv.Months)*30*day + time.Duration(iv.Days)*day + time.Duration(iv.Microseconds)*time.Microsecond
	if d <= 0 {
		return 0, false
	}
	return d, true
}

// clamp returns min(dur, ruleMax if set else maxTTL, maxTTL).
func (s *Service) clamp(dur time.Duration, ruleMax pgtype.Interval) time.Duration {
	granted := dur
	if ceiling, ok := intervalToDuration(ruleMax); ok {
		if granted > ceiling {
			granted = ceiling
		}
	}
	if granted > s.maxTTL {
		granted = s.maxTTL
	}
	return granted
}

// durationToInterval encodes a positive duration as a Microseconds interval.
func durationToInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: int64(d / time.Microsecond), Valid: true}
}

// toRequest maps a sqlc.AccessRequest plus derived fields to the DTO.
func toRequest(r sqlc.AccessRequest, approvals int, grantID uuid.UUID) Request {
	out := Request{
		ID:                r.ID,
		RequesterID:       r.RequesterUserID,
		RoleID:            r.RoleID,
		AssetID:           r.AssetID,
		Status:            r.Status,
		RequiredApprovals: int(r.RequiredApprovals),
		ApprovalsSoFar:    approvals,
		Reason:            r.Reason,
		CreatedAt:         r.CreatedAt,
		GrantID:           grantID,
	}
	if r.ResolvedAt.Valid {
		out.ResolvedAt = r.ResolvedAt.Time
	}
	return out
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// RequestAccess opens a JIT access request for (roleID, assetID). A self-service
// policy (required_approvals=0) mints the grant immediately.
func (s *Service) RequestAccess(ctx context.Context, requester, roleID, assetID uuid.UUID, dur time.Duration, reason string) (Request, error) {
	// Governance: eligibility is STANDING-only (a JIT grant does NOT confer it).
	eligible, err := s.resolver.IsEligibleRequester(ctx, requester, roleID, assetID)
	if err != nil {
		return Request{}, err
	}
	if !eligible {
		return Request{}, ErrNotEligible
	}
	rule, err := s.resolver.EffectiveRule(ctx, roleID, assetID)
	if err != nil {
		return Request{}, err
	}
	if rule == nil {
		return Request{}, ErrNotRequestable
	}
	// HoldsRole counts active grants: if the caller already has it active, refuse.
	held, err := s.roles.HoldsRole(ctx, requester, roleID, "asset", assetID)
	if err != nil {
		return Request{}, err
	}
	if held {
		return Request{}, ErrAlreadyActive
	}

	granted := s.clamp(dur, rule.MaxDuration)
	if granted <= 0 {
		return Request{}, ErrNotRequestable
	}

	selfService := rule.RequiredApprovals == 0
	status := "pending"
	if selfService {
		status = "granted"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	req, err := q.CreateAccessRequest(ctx, sqlc.CreateAccessRequestParams{
		RequesterUserID:   requester,
		RoleID:            roleID,
		AssetID:           assetID,
		Reason:            reason,
		RequestedDuration: durationToInterval(dur),
		RequiredApprovals: int32(rule.RequiredApprovals), //nolint:gosec // bounded ≥0 by policy constraint
		GrantedDuration:   durationToInterval(granted),
		Status:            status,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Request{}, ErrDuplicatePending
		}
		return Request{}, fmt.Errorf("create access request: %w", err)
	}

	var grantID uuid.UUID
	if selfService {
		grant, err := s.mintGrant(ctx, q, req, granted)
		if err != nil {
			return Request{}, err
		}
		grantID = grant.ID
		if err := q.SetAccessRequestStatus(ctx, sqlc.SetAccessRequestStatusParams{
			Status:     "granted",
			ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			ID:         req.ID,
		}); err != nil {
			return Request{}, fmt.Errorf("resolve self-service request: %w", err)
		}
	}
	if err := s.enqueue(ctx, q, EventRequestCreated, requester, req, nil); err != nil {
		return Request{}, err
	}
	if selfService {
		if err := s.enqueueGrant(ctx, q, requester, req, grantID); err != nil {
			return Request{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("commit: %w", err)
	}

	approvalsSoFar := 0
	return toRequest(req, approvalsSoFar, grantID), nil
}

// Approve records approver's approval; the Nth distinct approval mints the grant.
func (s *Service) Approve(ctx context.Context, approver, requestID uuid.UUID) (Request, error) {
	return s.vote(ctx, approver, requestID, "approve")
}

// Deny records approver's denial, immediately denying the request.
func (s *Service) Deny(ctx context.Context, approver, requestID uuid.UUID) (Request, error) {
	return s.vote(ctx, approver, requestID, "deny")
}

func (s *Service) vote(ctx context.Context, approver, requestID uuid.UUID, decision string) (Request, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	req, err := q.GetAccessRequestForUpdate(ctx, requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotPending
	}
	if err != nil {
		return Request{}, fmt.Errorf("lock request: %w", err)
	}
	if req.Status != "pending" {
		return Request{}, ErrNotPending
	}

	// Governance: approver eligibility is STANDING-only (a JIT grant does NOT confer it).
	ok, err := s.resolver.IsApprover(ctx, approver, req.RoleID, req.AssetID)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, ErrNotApprover
	}
	if approver == req.RequesterUserID {
		return Request{}, ErrSelfApprove
	}

	if _, err := q.AddApproval(ctx, sqlc.AddApprovalParams{
		RequestID:      requestID,
		ApproverUserID: approver,
		Decision:       decision,
	}); err != nil {
		if isUniqueViolation(err) {
			return Request{}, ErrAlreadyVoted
		}
		return Request{}, fmt.Errorf("add approval: %w", err)
	}

	var (
		grantID uuid.UUID
		granted bool
	)
	if decision == "deny" {
		if err := q.SetAccessRequestStatus(ctx, sqlc.SetAccessRequestStatusParams{
			Status:     "denied",
			ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			ID:         requestID,
		}); err != nil {
			return Request{}, fmt.Errorf("deny request: %w", err)
		}
		req.Status = "denied"
	} else {
		count, err := q.CountApprovals(ctx, requestID)
		if err != nil {
			return Request{}, fmt.Errorf("count approvals: %w", err)
		}
		if count >= int64(req.RequiredApprovals) {
			gr, err := s.mintGrant(ctx, q, req, mustDuration(req.GrantedDuration))
			if err != nil {
				return Request{}, err
			}
			grantID = gr.ID
			granted = true
			if err := q.SetAccessRequestStatus(ctx, sqlc.SetAccessRequestStatusParams{
				Status:     "granted",
				ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
				ID:         requestID,
			}); err != nil {
				return Request{}, fmt.Errorf("grant request: %w", err)
			}
			req.Status = "granted"
		}
	}

	// Read the final approval count inside the tx for the returned DTO.
	approvalsSoFar, err := q.CountApprovals(ctx, requestID)
	if err != nil {
		return Request{}, fmt.Errorf("count approvals: %w", err)
	}

	if decision == "deny" {
		if err := s.enqueue(ctx, q, EventRequestDenied, approver, req, nil); err != nil {
			return Request{}, err
		}
	} else {
		if err := s.enqueue(ctx, q, EventRequestApproved, approver, req, nil); err != nil {
			return Request{}, err
		}
		if granted {
			if err := s.enqueueGrant(ctx, q, approver, req, grantID); err != nil {
				return Request{}, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("commit: %w", err)
	}
	return toRequest(req, int(approvalsSoFar), grantID), nil
}

// Cancel cancels the requester's own pending request.
func (s *Service) Cancel(ctx context.Context, requester, requestID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	req, err := q.GetAccessRequestForUpdate(ctx, requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotPending
	}
	if err != nil {
		return fmt.Errorf("lock request: %w", err)
	}
	if req.RequesterUserID != requester {
		return ErrNotRequester
	}
	if req.Status != "pending" {
		return ErrNotPending
	}
	if err := q.SetAccessRequestStatus(ctx, sqlc.SetAccessRequestStatusParams{
		Status:     "cancelled",
		ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ID:         requestID,
	}); err != nil {
		return fmt.Errorf("cancel request: %w", err)
	}
	req.Status = "cancelled"
	if err := s.enqueue(ctx, q, EventRequestCancelled, requester, req, nil); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mintGrant inserts the access_grant for a granted request. Shared by
// RequestAccess (self-service) and Approve (threshold reached). The tx-scoped
// UNIQUE(request_id) is the backstop against a duplicate grant under concurrency.
func (s *Service) mintGrant(ctx context.Context, q *sqlc.Queries, req sqlc.AccessRequest, granted time.Duration) (sqlc.AccessGrant, error) {
	grant, err := q.CreateAccessGrant(ctx, sqlc.CreateAccessGrantParams{
		RequestID:     req.ID,
		RoleID:        req.RoleID,
		ScopeAssetID:  req.AssetID,
		SubjectUserID: req.RequesterUserID,
		ExpiresAt:     pgtype.Timestamptz{Time: time.Now().Add(granted), Valid: true},
	})
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("mint grant: %w", err)
	}
	return grant, nil
}

// mustDuration converts a stored granted_duration interval to a Duration; if the
// interval is somehow invalid it falls back to a safe non-zero minimum so a
// granted request always yields a live grant window.
func mustDuration(iv pgtype.Interval) time.Duration {
	if d, ok := intervalToDuration(iv); ok {
		return d
	}
	return time.Minute
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

// approvablePending resolves, in ONE set-based query, the pending access requests the
// caller may approve (with their current approve-count) — reproducing IsApprover over
// the whole candidate set instead of per row (which was an N+1: EffectiveRule +
// subject check + optional HoldsRoleStanding + CountApprovals, all per request). A
// candidate is included when the caller is neither its requester nor deactivated AND,
// for the request's EFFECTIVE policy (most-specific of asset / folder-ancestor /
// global by the same precedence as EffectiveRule), the caller is either an explicit
// `approver` subject (direct or via a nested group) OR holds the policy's approver_role
// STANDING on the asset. The standing arm reuses the shared authz_held_standing SQL
// function — the same relation HoldsRoleStanding checks — so governance semantics
// cannot drift; the effective policy is authz_effective_request_policy. restrict limits the candidate set to those request ids (a
// keyset page); a nil slice (SQL NULL) considers all pending requests. Results are
// ordered created_at DESC, id, matching the paged SQL page order.
//
// RESTRICT CONTRACT: pass nil for "all". A nil []uuid.UUID encodes as SQL NULL (the
// `@restrict IS NULL` all-arm); an EMPTY non-nil slice encodes as `'{}'` → `id = ANY('{}')`
// → zero rows. Callers must never pass []uuid.UUID{} to mean "all" (the paged callers
// guard this with a len(rows)==0 early return before building the id slice).
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

// enqueue writes a request-lifecycle audit event into the outbox on the caller's
// tx-bound querier, so it commits atomically with the domain write. Returns an
// error so an enqueue failure rolls back the domain action.
func (s *Service) enqueue(ctx context.Context, q *sqlc.Queries, eventType string, actor uuid.UUID, req sqlc.AccessRequest, extra map[string]any) error {
	if s.audit == nil {
		return nil
	}
	details := map[string]any{
		"request_id": req.ID.String(),
		"role_id":    req.RoleID.String(),
		"asset_id":   req.AssetID.String(),
		"requester":  req.RequesterUserID.String(),
		"status":     req.Status,
	}
	for k, v := range extra {
		details[k] = v
	}
	raw, _ := json.Marshal(details)
	return s.audit.Enqueue(ctx, q, audit.Event{
		Type:    eventType,
		ActorID: actor,
		Subject: "access_request:" + req.ID.String(),
		Details: raw,
	})
}

// enqueueGrant writes the grant-activation audit event into the outbox on the
// caller's tx-bound querier (atomic with the domain write).
func (s *Service) enqueueGrant(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, req sqlc.AccessRequest, grantID uuid.UUID) error {
	if s.audit == nil {
		return nil
	}
	details := map[string]any{
		"request_id": req.ID.String(),
		"grant_id":   grantID.String(),
		"role_id":    req.RoleID.String(),
		"asset_id":   req.AssetID.String(),
		"subject":    req.RequesterUserID.String(),
	}
	raw, _ := json.Marshal(details)
	return s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventGrantActivated,
		ActorID: actor,
		Subject: "access_grant:" + grantID.String(),
		Details: raw,
	})
}

// RevokeGrant revokes a single access_grant. The caller may revoke if they hold
// the management revoke capability (mgmtAuthorized, decided by the RPC layer via a
// capability check — admins hold ** so this is a no-op for them), the grant's
// subject (self-revoke), or a STANDING approver for the grant's (role, asset) —
// symmetric with approval authority. On success the revocation is audited and the
// terminator is notified so live sessions relying on the grant are torn down (both
// post-commit, best-effort).
func (s *Service) RevokeGrant(ctx context.Context, caller auth.CurrentUser, mgmtAuthorized bool, grantID uuid.UUID, reason string) (sqlc.AccessGrant, error) {
	g, err := sqlc.New(s.pool).GetGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AccessGrant{}, ErrGrantNotFound
	}
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("get grant: %w", err)
	}

	authorized := mgmtAuthorized || g.SubjectUserID == caller.ID
	if !authorized {
		ok, err := s.resolver.IsApprover(ctx, caller.ID, g.RoleID, g.ScopeAssetID)
		if err != nil {
			return sqlc.AccessGrant{}, err
		}
		authorized = ok
	}
	if !authorized {
		return sqlc.AccessGrant{}, ErrRevokeForbidden
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	revoked, err := q.RevokeGrant(ctx, sqlc.RevokeGrantParams{
		ID:            grantID,
		RevokedBy:     pgtype.UUID{Bytes: caller.ID, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// 0 rows updated: the grant was already revoked or has no live window.
		return sqlc.AccessGrant{}, ErrGrantInactive
	}
	if err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("revoke grant: %w", err)
	}

	if err := s.enqueueRevoked(ctx, q, caller.ID, revoked); err != nil {
		return sqlc.AccessGrant{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AccessGrant{}, fmt.Errorf("commit: %w", err)
	}

	s.terminate(ctx, revoked.ID)
	return revoked, nil
}

// RevokeGrantsForUser revokes ALL of a user's active grants (used by the
// deactivation cascade). Each revoked grant is audited and its sessions
// terminated. Returns the number of grants revoked.
func (s *Service) RevokeGrantsForUser(ctx context.Context, actor, userID uuid.UUID, reason string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	revoked, err := q.RevokeActiveGrantsForUser(ctx, sqlc.RevokeActiveGrantsForUserParams{
		SubjectUserID: userID,
		RevokedBy:     pgtype.UUID{Bytes: actor, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if err != nil {
		return 0, fmt.Errorf("revoke grants for user: %w", err)
	}
	for _, g := range revoked {
		if err := s.enqueueRevoked(ctx, q, actor, g); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	for _, g := range revoked {
		s.terminate(ctx, g.ID)
	}
	return len(revoked), nil
}

// DeleteRoleCascade deletes a role and everything that references it, in one
// transaction, so that "the role is gone" implies no one holds it and any live
// sessions it granted are torn down. The blast radius, by table:
//
//   - role_bindings (role_id = role): DELETED — the standing grants of the role.
//   - role_grants (role_id OR source_role_id = role): DELETED — every rewrite edge
//     touching the role, in either direction.
//   - request_policies (role_id = role): DELETED, along with their
//     request_policy_subjects — a requestability rule is meaningless without its
//     requestable role.
//   - request_policies referencing the role only as requester_role_id/approver_role_id:
//     SURVIVE, with that column set NULL (the policy loses only that gate). The FK on
//     those columns is ON DELETE RESTRICT, so this NULL-out MUST precede the role
//     delete or Postgres rejects it.
//   - access_grants (role_id = role, still live): REVOKED (revoked_at stamped) via the
//     existing revoke query, so the revocation is audited and the terminator is
//     notified — tearing down the live sessions those grants authorized. (The grant
//     rows are then removed by the roles FK cascade; the standing-authz-removal sweep,
//     triggered by the binding/edge deletes above, is the level-triggered backstop.)
//   - roles (the role): DELETED last. Its name uniqueness is enforced by partial
//     UNIQUE indexes on the roles table, so deleting the row frees the name; there is
//     no separate name-registry entry to clean up.
//
// Audit events (each revoked grant) are enqueued INSIDE the tx (atomic with the
// deletion); terminator notification is POST-COMMIT (it must not fire for a change
// that then rolls back), mirroring RevokeGrant/RevokeGrantsForUser.
func (s *Service) DeleteRoleCascade(ctx context.Context, actor, roleID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	// Revoke the role's still-live grants first (before the FK cascade removes the
	// rows), auditing each so the terminator can tear down their live sessions.
	revoked, err := q.RevokeActiveGrantsForRole(ctx, sqlc.RevokeActiveGrantsForRoleParams{
		RoleID:        roleID,
		RevokedBy:     pgtype.UUID{Bytes: actor, Valid: true},
		RevokedReason: pgtype.Text{String: "role_deleted", Valid: true},
	})
	if err != nil {
		return fmt.Errorf("revoke grants for role: %w", err)
	}
	for _, g := range revoked {
		if err := s.enqueueRevoked(ctx, q, actor, g); err != nil {
			return err
		}
	}

	// Standing references: bindings and rewrite edges (both directions).
	if err := q.DeleteRoleBindingsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role bindings: %w", err)
	}
	if err := q.DeleteRoleGrantsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role grants: %w", err)
	}

	// Request policies: delete those FOR the role (and their subjects); clear the
	// requester/approver gate on policies that only reference it (RESTRICT FKs, so
	// this must happen before the role delete).
	if err := q.DeletePolicySubjectsForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete policy subjects: %w", err)
	}
	if err := q.DeletePoliciesForRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}
	if err := q.NullRequesterRoleForRole(ctx, pgtype.UUID{Bytes: roleID, Valid: true}); err != nil {
		return fmt.Errorf("null requester role: %w", err)
	}
	if err := q.NullApproverRoleForRole(ctx, pgtype.UUID{Bytes: roleID, Valid: true}); err != nil {
		return fmt.Errorf("null approver role: %w", err)
	}

	// Finally the role itself (frees the name; FK-cascades the revoked grant rows
	// and any access_requests).
	if err := q.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	// Post-commit teardown of the sessions the revoked grants authorized.
	for _, g := range revoked {
		s.terminate(ctx, g.ID)
	}
	return nil
}

// ListMyGrants returns the caller's own grants (active + past), newest first.
func (s *Service) ListMyGrants(ctx context.Context, subject uuid.UUID) ([]Grant, error) {
	rows, err := sqlc.New(s.pool).ListGrantsBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list my grants: %w", err)
	}
	return toGrants(rows), nil
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

// ListMyGrantsPaged returns the caller's own grants with keyset pagination on
// (granted_at DESC, id ASC).
func (s *Service) ListMyGrantsPaged(ctx context.Context, subject uuid.UUID, page PageParams) ([]Grant, error) {
	params := sqlc.ListGrantsBySubjectPagedParams{
		SubjectUserID: subject,
		Lim:           page.Limit,
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsBySubjectPaged(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list my grants paged: %w", err)
	}
	return toGrants(rows), nil
}

// ListGrantsPaged returns grants for admin introspection with keyset pagination
// on (granted_at DESC, id ASC). Filters (subject, active_only) are preserved.
func (s *Service) ListGrantsPaged(ctx context.Context, filter GrantFilter, page PageParams) ([]Grant, error) {
	params := sqlc.ListGrantsFilteredPagedParams{
		ActiveOnly: filter.ActiveOnly,
		Lim:        page.Limit,
	}
	if filter.Subject != uuid.Nil {
		params.SubjectUserID = pgtype.UUID{Bytes: filter.Subject, Valid: true}
	}
	if page.AfterTs != nil {
		params.AfterTs = pgtype.Timestamptz{Time: *page.AfterTs, Valid: true}
		params.AfterID = pgtype.UUID{Bytes: page.AfterID, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsFilteredPaged(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list grants paged: %w", err)
	}
	return toGrants(rows), nil
}

// ListReviewableGrantsPaged returns grants the caller may review — grants where
// the caller is the subject OR a standing potential approver of the grant's
// originating (role, asset) — with keyset pagination on (granted_at DESC, id ASC).
//
// It fetches an unfiltered SQL page (all subjects, active_only=false so past and
// revoked grants remain reviewable) then filters in Go per row, exactly like
// ListPendingApprovalsPaged: the returned cursor tracks the LAST SQL ROW scanned
// (not the last kept row), so a page emits a next-cursor whenever the SQL page
// was full even if every row was filtered out — the client then resumes past the
// filtered rows rather than stopping early. The per-row filter IS the authz for
// this caller-scoped list (no capability gate).
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

// reviewableGrants resolves, in ONE set-based query, the grants the caller may review
// — reproducing CanReviewGrant over the whole candidate set instead of per row (the
// per-grant IsApprover N+1). A grant is reviewable when the caller is its subject OR
// (the caller is active AND, for the grant's (role, asset) EFFECTIVE policy — same
// asset/folder-ancestor/global precedence as EffectiveRule — an explicit approver
// subject, direct or via a nested group, OR the approver_role held STANDING on the
// asset). The subject arm intentionally has no active-user check, matching
// CanReviewGrant. The standing arm reuses the shared authz_held_standing SQL
// function, single-sourced with Check/HoldsRoleStanding, and the effective policy is
// authz_effective_request_policy. restrict limits the candidate set to those grant
// ids (a keyset page); a nil slice (SQL NULL) considers all grants. Ordered
// granted_at DESC, id to match the paged SQL page.
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

// PageParams carries decoded keyset cursor fields for time-ordered lists.
// AfterTs and AfterID are zero/nil when on the first page.
type PageParams struct {
	AfterTs *time.Time
	AfterID uuid.UUID
	Limit   int64
}

// PageCursor is a keyset position that can be encoded into a next-page token.
// It carries the (created_at, id) of the LAST SQL ROW SCANNED, which may
// differ from the last row returned when Go-side filtering drops rows.
type PageCursor struct {
	Ts time.Time
	ID uuid.UUID
}

// GrantFilter narrows an admin grant listing. Subject uuid.Nil = any subject.
type GrantFilter struct {
	Subject    uuid.UUID
	ActiveOnly bool
}

// ListGrants returns grants for admin introspection (active + past), optionally
// filtered by subject and/or active-only.
func (s *Service) ListGrants(ctx context.Context, filter GrantFilter) ([]Grant, error) {
	params := sqlc.ListGrantsFilteredParams{ActiveOnly: filter.ActiveOnly}
	if filter.Subject != uuid.Nil {
		params.SubjectUserID = pgtype.UUID{Bytes: filter.Subject, Valid: true}
	}
	rows, err := sqlc.New(s.pool).ListGrantsFiltered(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return toGrants(rows), nil
}

// GrantDTO maps a raw sqlc.AccessGrant to the transport DTO (used by handlers
// that receive the revoked grant from RevokeGrant).
func (s *Service) GrantDTO(g sqlc.AccessGrant) Grant { return toGrant(g) }

// toGrant maps a sqlc.AccessGrant to the DTO, deriving the active flag.
func toGrant(g sqlc.AccessGrant) Grant {
	out := Grant{
		ID:            g.ID,
		RoleID:        g.RoleID,
		AssetID:       g.ScopeAssetID,
		SubjectUserID: g.SubjectUserID,
		GrantedAt:     g.GrantedAt,
		ExpiresAt:     g.ExpiresAt,
		Active:        !g.RevokedAt.Valid && g.ExpiresAt.After(time.Now()),
	}
	if g.RevokedAt.Valid {
		out.RevokedAt = g.RevokedAt.Time
	}
	if g.RevokedReason.Valid {
		out.RevokedReason = g.RevokedReason.String
	}
	return out
}

func toGrants(rows []sqlc.AccessGrant) []Grant {
	out := make([]Grant, 0, len(rows))
	for _, g := range rows {
		out = append(out, toGrant(g))
	}
	return out
}

// terminate notifies the terminator that grantID's sessions must be torn down.
// Best-effort: a terminator error is logged, not returned (mirrors audit append).
func (s *Service) terminate(ctx context.Context, grantID uuid.UUID) {
	if s.terminator == nil {
		return
	}
	if err := s.terminator.TerminateGrant(ctx, grantID); err != nil {
		slog.Error("grant terminator failed", "grant_id", grantID.String(), "err", err)
	}
}

// enqueueRevoked writes the grant-revocation audit event into the outbox on the
// caller's tx-bound querier (atomic with the domain write).
func (s *Service) enqueueRevoked(ctx context.Context, q *sqlc.Queries, actor uuid.UUID, g sqlc.AccessGrant) error {
	if s.audit == nil {
		return nil
	}
	reason := ""
	if g.RevokedReason.Valid {
		reason = g.RevokedReason.String
	}
	details := map[string]any{
		"grant_id":   g.ID.String(),
		"request_id": g.RequestID.String(),
		"role_id":    g.RoleID.String(),
		"asset_id":   g.ScopeAssetID.String(),
		"subject":    g.SubjectUserID.String(),
		"reason":     reason,
	}
	raw, _ := json.Marshal(details)
	return s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventGrantRevoked,
		ActorID: actor,
		Subject: "access_grant:" + g.ID.String(),
		Details: raw,
	})
}
