package accessrequest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

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

	// Re-assert requester eligibility at approve time. A request can sit pending
	// while the requester loses eligibility — deactivated, or their standing
	// requester-role binding removed. IsEligibleRequester enforces active-user and
	// standing-only eligibility, so this fails closed on any such change and prevents
	// minting a grant no one would authorize now. (Denials still proceed — a denied
	// vote on an ineligible requester is harmless and resolves the request.)
	if decision == "approve" {
		eligible, err := s.resolver.IsEligibleRequester(ctx, req.RequesterUserID, req.RoleID, req.AssetID)
		if err != nil {
			return Request{}, err
		}
		if !eligible {
			return Request{}, ErrRequesterIneligible
		}
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
