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
type Resolver struct{ pool *pgxpool.Pool }

// New constructs a Resolver.
func New(pool *pgxpool.Pool) *Resolver { return &Resolver{pool: pool} }

// EffectiveRule returns the most-specific request policy for activating roleID on
// assetID: asset override > nearest ancestor folder override > role-level default
// (scope NULL). Returns (nil, nil) when no policy exists — the role is not
// JIT-requestable on that asset.
func (r *Resolver) EffectiveRule(ctx context.Context, roleID, assetID uuid.UUID) (*Rule, error) {
	const sql = `
WITH RECURSIVE ancestors(folder_id, depth) AS (
    SELECT folder_id, 0 FROM assets WHERE id = @assetID
  UNION ALL
    SELECT f.parent_id, a.depth + 1 FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
),
candidates(id, required_approvals, approver_role_id, requester_role_id, max_duration, spec) AS (
    SELECT id, required_approvals, approver_role_id, requester_role_id, max_duration, 0 FROM request_policies WHERE role_id = @roleID AND scope_asset_id = @assetID
  UNION ALL
    SELECT rp.id, rp.required_approvals, rp.approver_role_id, rp.requester_role_id, rp.max_duration, a.depth + 1
    FROM request_policies rp JOIN ancestors a ON rp.scope_folder_id = a.folder_id WHERE rp.role_id = @roleID
  UNION ALL
    SELECT id, required_approvals, approver_role_id, requester_role_id, max_duration, 1000000 FROM request_policies WHERE role_id = @roleID AND scope_folder_id IS NULL AND scope_asset_id IS NULL
)
SELECT id, required_approvals, approver_role_id, requester_role_id, max_duration FROM candidates ORDER BY spec ASC LIMIT 1`
	var id uuid.UUID
	var req int32
	var approver pgtype.UUID
	var requester pgtype.UUID
	var maxDuration pgtype.Interval
	err := r.pool.QueryRow(ctx, sql, pgx.NamedArgs{"roleID": roleID, "assetID": assetID}).Scan(&id, &req, &approver, &requester, &maxDuration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("effective rule: %w", err)
	}
	rule := &Rule{ID: id, RequiredApprovals: int(req), MaxDuration: maxDuration}
	if approver.Valid {
		rule.ApproverRoleID = uuid.UUID(approver.Bytes)
	}
	if requester.Valid {
		rule.RequesterRoleID = uuid.UUID(requester.Bytes)
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
	// to kind='approver' so requester subjects never count as approvers.
	const sql = `
WITH RECURSIVE user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = @userID
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects ara
    WHERE ara.policy_id = @policyID
      AND ara.kind = 'approver'
      AND (ara.subject_user_id = @userID OR ara.subject_group_id IN (SELECT group_id FROM user_groups))
      -- a deactivated user counts for nothing
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = @userID AND u.deactivated_at IS NULL)
)`
	var explicit bool
	if err := r.pool.QueryRow(ctx, sql, pgx.NamedArgs{"userID": approverUserID, "policyID": rule.ID}).Scan(&explicit); err != nil {
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
	// to kind='requester'.
	const sql = `
WITH RECURSIVE user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = @userID
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects rps
    WHERE rps.policy_id = @policyID
      AND rps.kind = 'requester'
      AND (rps.subject_user_id = @userID OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
      -- a deactivated user counts for nothing
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = @userID AND u.deactivated_at IS NULL)
)`
	var explicit bool
	if err := r.pool.QueryRow(ctx, sql, pgx.NamedArgs{"userID": requesterUserID, "policyID": rule.ID}).Scan(&explicit); err != nil {
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
