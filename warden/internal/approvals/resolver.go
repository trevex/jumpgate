// Package approvals resolves approval rules (most-specific (role,scope)) and
// whether a user may approve a given role activation.
package approvals

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Rule is an effective request policy for activating a role on an asset.
type Rule struct {
	ID                uuid.UUID
	RequiredApprovals int
	ApproverRoleID    uuid.UUID       // uuid.Nil when the policy has no approver-role source
	RequesterRoleID   uuid.UUID       // uuid.Nil when the policy has no requester-role source
	MaxDuration       pgtype.Interval // invalid/zero when the policy has no per-scope duration cap (NULL)
}

// Resolver answers approval questions over the control-plane Postgres.
type Resolver struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New constructs a Resolver.
func New(pool *pgxpool.Pool) *Resolver { return &Resolver{pool: pool, q: sqlc.New(pool)} }

// EffectiveRule returns the most-specific request policy for activating roleID on
// assetID: asset override > nearest ancestor folder override > role-level default
// (scope NULL). Returns (nil, nil) when no policy exists — the role is not
// JIT-requestable on that asset.
func (r *Resolver) EffectiveRule(ctx context.Context, roleID, assetID uuid.UUID) (*Rule, error) {
	row, err := r.q.EffectiveRequestPolicy(ctx, sqlc.EffectiveRequestPolicyParams{RoleID: roleID, AssetID: assetID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("effective rule: %w", err)
	}
	rule := &Rule{
		ID:                uuid.UUID(row.PolicyID.Bytes),
		RequiredApprovals: int(row.RequiredApprovals.Int32),
		MaxDuration:       row.MaxDuration,
	}
	if row.ApproverRoleID.Valid {
		rule.ApproverRoleID = uuid.UUID(row.ApproverRoleID.Bytes)
	}
	if row.RequesterRoleID.Valid {
		rule.RequesterRoleID = uuid.UUID(row.RequesterRoleID.Bytes)
	}
	return rule, nil
}

// IsApprover reports whether approverUserID may approve activating requestRoleID
// on assetID, per the effective policy: explicit approver subjects (from
// request_policy_subjects with kind='approver') ∪ STANDING holders of the policy's
// approver_role on the asset, resolved through the explicit role-rewrite graph
// (HoldsRoleStanding).
//
// GOVERNANCE (M3c): the approver_role branch uses HoldsRoleStanding, NOT HoldsRole
// — a role obtained via a JIT access_grant gives access but MUST NOT confer
// approver eligibility. Only a standing binding of the approver_role qualifies.
func (r *Resolver) IsApprover(ctx context.Context, approverUserID, requestRoleID, assetID uuid.UUID) (bool, error) {
	rule, err := r.EffectiveRule(ctx, requestRoleID, assetID)
	if err != nil {
		return false, err
	}
	if rule == nil {
		return false, nil
	}

	// Explicit approver subjects: direct user or (nested) group match, restricted
	// to kind='approver' so requester subjects never count as approvers. A
	// deactivated user counts for nothing (authz_user_is_active inside the query).
	explicit, err := r.q.ApproverSubjectExists(ctx, sqlc.ApproverSubjectExistsParams{
		PolicyID: rule.ID,
		User:     pgtype.UUID{Bytes: approverUserID, Valid: true},
	})
	if err != nil {
		return false, fmt.Errorf("is approver (explicit): %w", err)
	}
	if explicit {
		return true, nil
	}

	// Approver-role branch: the approver qualifies if they hold the policy's
	// approver_role on the asset via the explicit role-rewrite graph (including
	// rewrites) THROUGH A STANDING BINDING. HoldsRoleStanding (not HoldsRole)
	// excludes active JIT access_grants: a granted approver_role does NOT make you
	// an approver.
	if rule.ApproverRoleID != uuid.Nil {
		holds, err := authz.NewRoleResolver(r.pool).HoldsRoleStanding(ctx, approverUserID, rule.ApproverRoleID, "asset", assetID)
		if err != nil {
			return false, fmt.Errorf("is approver (role): %w", err)
		}
		return holds, nil
	}
	return false, nil
}

// IsEligibleRequester reports whether requesterUserID may request activating
// requestRoleID on assetID, per the effective policy: eligibility holds when the
// requester holds the policy's requester_role on the asset via the explicit
// role-rewrite graph THROUGH A STANDING BINDING (HoldsRoleStanding) OR is an
// explicit requester subject (from request_policy_subjects with kind='requester').
// Mirrors IsApprover.
//
// GOVERNANCE (M3c): the requester_role branch uses HoldsRoleStanding, NOT HoldsRole
// — a role obtained via a JIT access_grant gives access but MUST NOT confer
// request eligibility. Only a standing binding of the requester_role qualifies.
func (r *Resolver) IsEligibleRequester(ctx context.Context, requesterUserID, requestRoleID, assetID uuid.UUID) (bool, error) {
	rule, err := r.EffectiveRule(ctx, requestRoleID, assetID)
	if err != nil {
		return false, err
	}
	if rule == nil {
		return false, nil
	}

	// Explicit requester subjects: direct user or (nested) group match, restricted
	// to kind='requester'. A deactivated user counts for nothing
	// (authz_user_is_active inside the query).
	explicit, err := r.q.RequesterSubjectExists(ctx, sqlc.RequesterSubjectExistsParams{
		PolicyID: rule.ID,
		User:     pgtype.UUID{Bytes: requesterUserID, Valid: true},
	})
	if err != nil {
		return false, fmt.Errorf("is eligible requester (explicit): %w", err)
	}
	if explicit {
		return true, nil
	}

	// Requester-role branch: the requester qualifies if they hold the policy's
	// requester_role on the asset via the explicit role-rewrite graph THROUGH A
	// STANDING BINDING. HoldsRoleStanding (not HoldsRole) excludes active JIT
	// access_grants: a granted requester_role does NOT make you an eligible requester.
	if rule.RequesterRoleID != uuid.Nil {
		holds, err := authz.NewRoleResolver(r.pool).HoldsRoleStanding(ctx, requesterUserID, rule.RequesterRoleID, "asset", assetID)
		if err != nil {
			return false, fmt.Errorf("is eligible requester (role): %w", err)
		}
		return holds, nil
	}
	return false, nil
}
