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
// AUDIT: audit.Logger.Append opens its own advisory-locked tx and therefore
// cannot join the domain tx. Audit events are appended AFTER the domain tx
// commits — appending inside the domain tx (while holding request row locks)
// would risk lock-ordering deadlocks against the audit advisory lock. The domain
// write is the source of truth; the audit entry follows the committed fact.
//
// KNOWN LIMITATION: because the audit append is post-commit, a crash in the
// window between the domain commit and the append leaves a durable action with
// no audit entry — a gap in the tamper-evident trail. An audit-append failure is
// logged loudly (slog.Error) but does NOT fail the RPC (the action already
// committed; failing would falsely report failure to the client). Closing the
// crash window fully needs a transactional audit outbox (write the event inside
// the domain tx, drain it with a worker) — deferred to a later milestone.
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
	"github.com/trevex/jumpgate/warden/internal/db/gen"
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
	audit      *audit.Logger
	resolver   *approvals.Resolver
	roles      *authz.RoleResolver
	terminator GrantTerminator
	maxTTL     time.Duration
}

// NewService constructs the access-request Service. A nil terminator defaults to
// NoopTerminator (session teardown is wired against the gateway in M4).
func NewService(pool *pgxpool.Pool, auditLog *audit.Logger, resolver *approvals.Resolver, roles *authz.RoleResolver, terminator GrantTerminator, maxTTL time.Duration) *Service {
	if maxTTL <= 0 {
		maxTTL = 8 * time.Hour
	}
	if terminator == nil {
		terminator = NoopTerminator{}
	}
	return &Service{pool: pool, audit: auditLog, resolver: resolver, roles: roles, terminator: terminator, maxTTL: maxTTL}
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

// toRequest maps a gen.AccessRequest plus derived fields to the DTO.
func toRequest(r gen.AccessRequest, approvals int, grantID uuid.UUID) Request {
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
	q := gen.New(tx)

	req, err := q.CreateAccessRequest(ctx, gen.CreateAccessRequestParams{
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
		if err := q.SetAccessRequestStatus(ctx, gen.SetAccessRequestStatusParams{
			Status:     "granted",
			ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			ID:         req.ID,
		}); err != nil {
			return Request{}, fmt.Errorf("resolve self-service request: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("commit: %w", err)
	}

	s.append(ctx, EventRequestCreated, requester, req, nil)
	if selfService {
		s.appendGrant(ctx, requester, req, grantID)
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
	q := gen.New(tx)

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

	if _, err := q.AddApproval(ctx, gen.AddApprovalParams{
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
		if err := q.SetAccessRequestStatus(ctx, gen.SetAccessRequestStatusParams{
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
			if err := q.SetAccessRequestStatus(ctx, gen.SetAccessRequestStatusParams{
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

	if err := tx.Commit(ctx); err != nil {
		return Request{}, fmt.Errorf("commit: %w", err)
	}

	if decision == "deny" {
		s.append(ctx, EventRequestDenied, approver, req, nil)
	} else {
		s.append(ctx, EventRequestApproved, approver, req, nil)
		if granted {
			s.appendGrant(ctx, approver, req, grantID)
		}
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
	q := gen.New(tx)

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
	if err := q.SetAccessRequestStatus(ctx, gen.SetAccessRequestStatusParams{
		Status:     "cancelled",
		ResolvedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ID:         requestID,
	}); err != nil {
		return fmt.Errorf("cancel request: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	req.Status = "cancelled"
	s.append(ctx, EventRequestCancelled, requester, req, nil)
	return nil
}

// mintGrant inserts the access_grant for a granted request. Shared by
// RequestAccess (self-service) and Approve (threshold reached). The tx-scoped
// UNIQUE(request_id) is the backstop against a duplicate grant under concurrency.
func (s *Service) mintGrant(ctx context.Context, q *gen.Queries, req gen.AccessRequest, granted time.Duration) (gen.AccessGrant, error) {
	grant, err := q.CreateAccessGrant(ctx, gen.CreateAccessGrantParams{
		RequestID:     req.ID,
		RoleID:        req.RoleID,
		ScopeAssetID:  req.AssetID,
		SubjectUserID: req.RequesterUserID,
		ExpiresAt:     time.Now().Add(granted),
	})
	if err != nil {
		return gen.AccessGrant{}, fmt.Errorf("mint grant: %w", err)
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
	q := gen.New(s.pool)
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
	q := gen.New(s.pool)
	rows, err := q.ListPendingRequests(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pending requests: %w", err)
	}
	out := make([]Request, 0)
	for _, r := range rows {
		if r.RequesterUserID == caller {
			continue
		}
		ok, err := s.resolver.IsApprover(ctx, caller, r.RoleID, r.AssetID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		count, err := q.CountApprovals(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("count approvals: %w", err)
		}
		out = append(out, toRequest(r, int(count), uuid.Nil))
	}
	return out, nil
}

// grantIDFor returns the grant id for a granted request, or uuid.Nil.
func (s *Service) grantIDFor(ctx context.Context, q *gen.Queries, r gen.AccessRequest) uuid.UUID {
	if r.Status != "granted" {
		return uuid.Nil
	}
	gr, err := q.GetGrantByRequest(ctx, r.ID)
	if err != nil {
		return uuid.Nil
	}
	return gr.ID
}

// append writes a request-lifecycle audit event (best-effort, post-commit).
func (s *Service) append(ctx context.Context, eventType string, actor uuid.UUID, req gen.AccessRequest, extra map[string]any) {
	if s.audit == nil {
		return
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
	if err := s.audit.Append(ctx, audit.Event{
		Type:    eventType,
		ActorID: actor,
		Subject: "access_request:" + req.ID.String(),
		Details: raw,
	}); err != nil {
		// The action already committed; do not fail the RPC. Log loudly — a
		// dropped audit event is a hole in the tamper-evident trail.
		slog.Error("audit append failed", "event", eventType, "request_id", req.ID.String(), "err", err)
	}
}

// appendGrant writes the grant-activation audit event.
func (s *Service) appendGrant(ctx context.Context, actor uuid.UUID, req gen.AccessRequest, grantID uuid.UUID) {
	if s.audit == nil {
		return
	}
	details := map[string]any{
		"request_id": req.ID.String(),
		"grant_id":   grantID.String(),
		"role_id":    req.RoleID.String(),
		"asset_id":   req.AssetID.String(),
		"subject":    req.RequesterUserID.String(),
	}
	raw, _ := json.Marshal(details)
	if err := s.audit.Append(ctx, audit.Event{
		Type:    EventGrantActivated,
		ActorID: actor,
		Subject: "access_grant:" + grantID.String(),
		Details: raw,
	}); err != nil {
		slog.Error("audit append failed", "event", EventGrantActivated, "grant_id", grantID.String(), "err", err)
	}
}

// RevokeGrant revokes a single access_grant. The caller may revoke if they are an
// admin, the grant's subject (self-revoke), or a STANDING approver for the grant's
// (role, asset) — symmetric with approval authority. On success the revocation is
// audited and the terminator is notified so live sessions relying on the grant are
// torn down (both post-commit, best-effort).
func (s *Service) RevokeGrant(ctx context.Context, caller auth.CurrentUser, grantID uuid.UUID, reason string) (gen.AccessGrant, error) {
	g, err := gen.New(s.pool).GetGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return gen.AccessGrant{}, ErrGrantNotFound
	}
	if err != nil {
		return gen.AccessGrant{}, fmt.Errorf("get grant: %w", err)
	}

	authorized := caller.IsAdmin || g.SubjectUserID == caller.ID
	if !authorized {
		ok, err := s.resolver.IsApprover(ctx, caller.ID, g.RoleID, g.ScopeAssetID)
		if err != nil {
			return gen.AccessGrant{}, err
		}
		authorized = ok
	}
	if !authorized {
		return gen.AccessGrant{}, ErrRevokeForbidden
	}

	revoked, err := gen.New(s.pool).RevokeGrant(ctx, gen.RevokeGrantParams{
		ID:            grantID,
		RevokedBy:     pgtype.UUID{Bytes: caller.ID, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// 0 rows updated: the grant was already revoked or has no live window.
		return gen.AccessGrant{}, ErrGrantInactive
	}
	if err != nil {
		return gen.AccessGrant{}, fmt.Errorf("revoke grant: %w", err)
	}

	s.appendRevoked(ctx, caller.ID, revoked)
	s.terminate(ctx, revoked.ID)
	return revoked, nil
}

// RevokeGrantsForUser revokes ALL of a user's active grants (used by the
// deactivation cascade). Each revoked grant is audited and its sessions
// terminated. Returns the number of grants revoked.
func (s *Service) RevokeGrantsForUser(ctx context.Context, actor, userID uuid.UUID, reason string) (int, error) {
	revoked, err := gen.New(s.pool).RevokeActiveGrantsForUser(ctx, gen.RevokeActiveGrantsForUserParams{
		SubjectUserID: userID,
		RevokedBy:     pgtype.UUID{Bytes: actor, Valid: true},
		RevokedReason: pgtype.Text{String: reason, Valid: true},
	})
	if err != nil {
		return 0, fmt.Errorf("revoke grants for user: %w", err)
	}
	for _, g := range revoked {
		s.appendRevoked(ctx, actor, g)
		s.terminate(ctx, g.ID)
	}
	return len(revoked), nil
}

// ListMyGrants returns the caller's own grants (active + past), newest first.
func (s *Service) ListMyGrants(ctx context.Context, subject uuid.UUID) ([]Grant, error) {
	rows, err := gen.New(s.pool).ListGrantsBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list my grants: %w", err)
	}
	return toGrants(rows), nil
}

// GrantFilter narrows an admin grant listing. Subject uuid.Nil = any subject.
type GrantFilter struct {
	Subject    uuid.UUID
	ActiveOnly bool
}

// ListGrants returns grants for admin introspection (active + past), optionally
// filtered by subject and/or active-only.
func (s *Service) ListGrants(ctx context.Context, filter GrantFilter) ([]Grant, error) {
	params := gen.ListGrantsFilteredParams{ActiveOnly: filter.ActiveOnly}
	if filter.Subject != uuid.Nil {
		params.SubjectUserID = pgtype.UUID{Bytes: filter.Subject, Valid: true}
	}
	rows, err := gen.New(s.pool).ListGrantsFiltered(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	return toGrants(rows), nil
}

// GrantDTO maps a raw gen.AccessGrant to the transport DTO (used by handlers
// that receive the revoked grant from RevokeGrant).
func (s *Service) GrantDTO(g gen.AccessGrant) Grant { return toGrant(g) }

// toGrant maps a gen.AccessGrant to the DTO, deriving the active flag.
func toGrant(g gen.AccessGrant) Grant {
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

func toGrants(rows []gen.AccessGrant) []Grant {
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

// appendRevoked writes the grant-revocation audit event (best-effort, post-commit).
func (s *Service) appendRevoked(ctx context.Context, actor uuid.UUID, g gen.AccessGrant) {
	if s.audit == nil {
		return
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
	if err := s.audit.Append(ctx, audit.Event{
		Type:    EventGrantRevoked,
		ActorID: actor,
		Subject: "access_grant:" + g.ID.String(),
		Details: raw,
	}); err != nil {
		slog.Error("audit append failed", "event", EventGrantRevoked, "grant_id", g.ID.String(), "err", err)
	}
}
