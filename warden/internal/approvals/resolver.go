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
)

// Rule is an effective approval rule for activating a role on an asset.
type Rule struct {
	ID                uuid.UUID
	RequiredApprovals int
	ApproverRoleID    uuid.UUID // uuid.Nil when the rule has no approver-role source
}

// Resolver answers approval questions over the control-plane Postgres.
type Resolver struct{ pool *pgxpool.Pool }

// New constructs a Resolver.
func New(pool *pgxpool.Pool) *Resolver { return &Resolver{pool: pool} }

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// EffectiveRule returns the most-specific approval rule for activating roleID on
// assetID: asset override > nearest ancestor folder override > role-level default
// (scope NULL). Returns (nil, nil) when no rule exists — the role is not
// JIT-requestable on that asset.
func (r *Resolver) EffectiveRule(ctx context.Context, roleID, assetID uuid.UUID) (*Rule, error) {
	const sql = `
WITH RECURSIVE ancestors(folder_id, depth) AS (
    SELECT folder_id, 0 FROM assets WHERE id = $2
  UNION ALL
    SELECT f.parent_id, a.depth + 1 FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
),
candidates(id, required_approvals, approver_role_id, spec) AS (
    SELECT id, required_approvals, approver_role_id, 0 FROM approval_rules WHERE role_id = $1 AND scope_asset_id = $2
  UNION ALL
    SELECT ar.id, ar.required_approvals, ar.approver_role_id, a.depth + 1
    FROM approval_rules ar JOIN ancestors a ON ar.scope_folder_id = a.folder_id WHERE ar.role_id = $1
  UNION ALL
    SELECT id, required_approvals, approver_role_id, 1000000 FROM approval_rules WHERE role_id = $1 AND scope_folder_id IS NULL AND scope_asset_id IS NULL
)
SELECT id, required_approvals, approver_role_id FROM candidates ORDER BY spec ASC LIMIT 1`
	var id uuid.UUID
	var req int32
	var approver pgtype.UUID
	err := r.pool.QueryRow(ctx, sql, roleID, assetID).Scan(&id, &req, &approver)
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
	return rule, nil
}

// IsApprover reports whether approverUserID may approve activating requestRoleID
// on assetID, per the effective rule (explicit approver subjects ∪ holders of the
// rule's approver_role as a standing binding on the asset or an ancestor folder).
func (r *Resolver) IsApprover(ctx context.Context, approverUserID, requestRoleID, assetID uuid.UUID) (bool, error) {
	rule, err := r.EffectiveRule(ctx, requestRoleID, assetID)
	if err != nil {
		return false, err
	}
	if rule == nil {
		return false, nil
	}
	const sql = `
WITH RECURSIVE user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
ancestors(folder_id) AS (
    SELECT folder_id FROM assets WHERE id = $3
  UNION ALL
    SELECT f.parent_id FROM folders f JOIN ancestors a ON f.id = a.folder_id WHERE f.parent_id IS NOT NULL
)
SELECT
  EXISTS (
    SELECT 1 FROM approval_rule_approvers ara
    WHERE ara.rule_id = $2
      AND (ara.subject_user_id = $1 OR ara.subject_group_id IN (SELECT group_id FROM user_groups))
  )
  OR (
    $4::uuid IS NOT NULL AND EXISTS (
      SELECT 1 FROM role_bindings rb
      WHERE rb.role_id = $4 AND rb.kind = 'standing'
        AND (rb.scope_asset_id = $3 OR rb.scope_folder_id IN (SELECT folder_id FROM ancestors))
        AND (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
    )
  )`
	var approverRole pgtype.UUID
	if rule.ApproverRoleID != uuid.Nil {
		approverRole = pgUUID(rule.ApproverRoleID)
	}
	var ok bool
	if err := r.pool.QueryRow(ctx, sql, approverUserID, rule.ID, assetID, approverRole).Scan(&ok); err != nil {
		return false, fmt.Errorf("is approver: %w", err)
	}
	return ok, nil
}
