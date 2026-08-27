package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// RoleResolver answers explicit role-rewrite membership questions. The backward
// goal-expansion closure lives in the DB (authz_role_goals / authz_role_goal_paths);
// this type reaches it through the static sqlc queries on q.
type RoleResolver struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// NewRoleResolver constructs a RoleResolver.
func NewRoleResolver(pool *pgxpool.Pool) *RoleResolver {
	return &RoleResolver{pool: pool, q: sqlc.New(pool)}
}

// HoldsRole reports whether userID holds roleID on the given object (objectKind is
// "asset" or "folder") — i.e. whether the user holds it via a standing role_binding
// OR an active JIT access_grant — resolving explicit role_grants rewrite rules
// (same_object + parent). Group-aware and cycle-safe. This is the ACCESS-membership
// predicate: a JIT-granted role counts. For the governance/eligibility predicate
// (grants excluded) use HoldsRoleStanding.
func (r *RoleResolver) HoldsRole(ctx context.Context, userID, roleID uuid.UUID, objectKind string, objectID uuid.UUID) (bool, error) {
	ok, err := r.q.HoldsRole(ctx, sqlc.HoldsRoleParams{
		RoleID:     roleID,
		ObjectKind: objectKind,
		ObjectID:   objectID,
		User:       pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return false, fmt.Errorf("holds role: %w", err)
	}
	return ok, nil
}

// HoldsRoleStanding reports whether userID holds roleID on the given object via a
// STANDING role_binding only (governance predicate — active JIT access_grants are
// EXCLUDED), resolving role_grants rewrite rules (same_object + parent). A role
// obtained via a JIT grant gives real access (HoldsRole) but MUST NOT confer
// governance eligibility, so IsApprover/IsEligibleRequester resolve their role
// branch through THIS method.
func (r *RoleResolver) HoldsRoleStanding(ctx context.Context, userID, roleID uuid.UUID, objectKind string, objectID uuid.UUID) (bool, error) {
	ok, err := r.q.HoldsRoleStanding(ctx, sqlc.HoldsRoleStandingParams{
		RoleID:     roleID,
		ObjectKind: objectKind,
		ObjectID:   objectID,
		User:       pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return false, fmt.Errorf("holds role standing: %w", err)
	}
	return ok, nil
}

// ExplainStep is one hop in a role-rewrite derivation path: the (role, object)
// goal reached and the rewrite arm (`direct` for the seed, `same_object`, or
// `parent`) that produced it.
type ExplainStep struct {
	RoleID     uuid.UUID
	ObjectKind string
	ObjectID   uuid.UUID
	Via        string
}

// ExplainPath is one complete derivation: the chain of goals from the seed to a
// goal satisfied by a standing binding, plus that binding's id and subject
// ("user:<uuid>" or "group:<uuid>").
type ExplainPath struct {
	Steps     []ExplainStep
	BindingID uuid.UUID
	Subject   string
}

// explainStepJSON mirrors the jsonb objects carried in the CTE path column.
type explainStepJSON struct {
	RoleID     string `json:"role_id"`
	ObjectKind string `json:"object_kind"`
	ObjectID   string `json:"object_id"`
	Via        string `json:"via"`
}

// ExplainRole enumerates every derivation by which userID holds roleID on the
// given asset, resolving role_grants rewrite rules (same_object + parent) down to
// standing bindings (direct or via nested groups). It reports "all the ways" as
// jsonb paths rather than a single boolean; the in-path cycle guard bounds each
// path to distinct (role,object) tuples (termination) without shrinking the goal
// set, so holds == (len(paths) > 0) is equivalent to HoldsRole. Unknown-but-
// parseable ids match nothing and yield holds=false, paths=nil (no error).
func (r *RoleResolver) ExplainRole(ctx context.Context, userID, roleID, assetID uuid.UUID) (bool, []ExplainPath, error) {
	rows, err := r.q.ExplainRolePaths(ctx, sqlc.ExplainRolePathsParams{User: userID, RoleID: roleID, AssetID: assetID})
	if err != nil {
		return false, nil, fmt.Errorf("explain role: %w", err)
	}

	var paths []ExplainPath
	for _, row := range rows {
		var rawSteps []explainStepJSON
		if err := json.Unmarshal(row.Path, &rawSteps); err != nil {
			return false, nil, fmt.Errorf("explain role decode path: %w", err)
		}
		steps := make([]ExplainStep, 0, len(rawSteps))
		for _, s := range rawSteps {
			rid, err := uuid.Parse(s.RoleID)
			if err != nil {
				return false, nil, fmt.Errorf("explain role bad step role_id: %w", err)
			}
			oid, err := uuid.Parse(s.ObjectID)
			if err != nil {
				return false, nil, fmt.Errorf("explain role bad step object_id: %w", err)
			}
			steps = append(steps, ExplainStep{RoleID: rid, ObjectKind: s.ObjectKind, ObjectID: oid, Via: s.Via})
		}
		var subject string
		switch {
		case row.SubjectUserID.Valid:
			subject = "user:" + uuid.UUID(row.SubjectUserID.Bytes).String()
		case row.SubjectGroupID.Valid:
			subject = "group:" + uuid.UUID(row.SubjectGroupID.Bytes).String()
		}
		paths = append(paths, ExplainPath{Steps: steps, BindingID: uuid.UUID(row.BindingID.Bytes), Subject: subject})
	}
	return len(paths) > 0, paths, nil
}
