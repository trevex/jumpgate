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
	ApproverRoleID    uuid.UUID // uuid.Nil when the policy has no approver-role source
	RequesterRoleID   uuid.UUID // uuid.Nil when the policy has no requester-role source
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
    SELECT folder_id, 0 FROM assets WHERE id = $2
  UNION ALL
    SELECT f.parent_id, a.depth + 1 FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
),
candidates(id, required_approvals, approver_role_id, requester_role_id, spec) AS (
    SELECT id, required_approvals, approver_role_id, requester_role_id, 0 FROM request_policies WHERE role_id = $1 AND scope_asset_id = $2
  UNION ALL
    SELECT rp.id, rp.required_approvals, rp.approver_role_id, rp.requester_role_id, a.depth + 1
    FROM request_policies rp JOIN ancestors a ON rp.scope_folder_id = a.folder_id WHERE rp.role_id = $1
  UNION ALL
    SELECT id, required_approvals, approver_role_id, requester_role_id, 1000000 FROM request_policies WHERE role_id = $1 AND scope_folder_id IS NULL AND scope_asset_id IS NULL
)
SELECT id, required_approvals, approver_role_id, requester_role_id FROM candidates ORDER BY spec ASC LIMIT 1`
	var id uuid.UUID
	var req int32
	var approver pgtype.UUID
	var requester pgtype.UUID
	err := r.pool.QueryRow(ctx, sql, roleID, assetID).Scan(&id, &req, &approver, &requester)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("effective rule: %w", err)
	}
	rule := &Rule{ID: id, RequiredApprovals: int(req)}
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
// request_policy_subjects with kind='approver') ∪ holders of the policy's
// approver_role on the asset, resolved through the explicit role-rewrite graph
// (HoldsRole).
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
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects ara
    WHERE ara.policy_id = $2
      AND ara.kind = 'approver'
      AND (ara.subject_user_id = $1 OR ara.subject_group_id IN (SELECT group_id FROM user_groups))
)`
	var explicit bool
	if err := r.pool.QueryRow(ctx, sql, approverUserID, rule.ID).Scan(&explicit); err != nil {
		return false, fmt.Errorf("is approver (explicit): %w", err)
	}
	if explicit {
		return true, nil
	}

	// Approver-role branch: the approver qualifies if they hold the policy's
	// approver_role on the asset via the explicit role-rewrite graph (including
	// rewrites), not just a direct standing binding.
	if rule.ApproverRoleID != uuid.Nil {
		holds, err := authz.NewRoleResolver(r.pool).HoldsRole(ctx, approverUserID, rule.ApproverRoleID, "asset", assetID)
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
// role-rewrite graph (HoldsRole) OR is an explicit requester subject (from
// request_policy_subjects with kind='requester'). Mirrors IsApprover. This is
// groundwork for a later task and is not yet wired into any RPC/visibility.
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
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
)
SELECT EXISTS (
    SELECT 1 FROM request_policy_subjects rps
    WHERE rps.policy_id = $2
      AND rps.kind = 'requester'
      AND (rps.subject_user_id = $1 OR rps.subject_group_id IN (SELECT group_id FROM user_groups))
)`
	var explicit bool
	if err := r.pool.QueryRow(ctx, sql, requesterUserID, rule.ID).Scan(&explicit); err != nil {
		return false, fmt.Errorf("is eligible requester (explicit): %w", err)
	}
	if explicit {
		return true, nil
	}

	// Requester-role branch: the requester qualifies if they hold the policy's
	// requester_role on the asset via the explicit role-rewrite graph.
	if rule.RequesterRoleID != uuid.Nil {
		holds, err := authz.NewRoleResolver(r.pool).HoldsRole(ctx, requesterUserID, rule.RequesterRoleID, "asset", assetID)
		if err != nil {
			return false, fmt.Errorf("is eligible requester (role): %w", err)
		}
		return holds, nil
	}
	return false, nil
}
