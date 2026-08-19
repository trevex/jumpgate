package authz

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleResolver answers explicit role-rewrite membership questions.
type RoleResolver struct{ pool *pgxpool.Pool }

// NewRoleResolver constructs a RoleResolver.
func NewRoleResolver(pool *pgxpool.Pool) *RoleResolver { return &RoleResolver{pool: pool} }

// holdsRoleGoalsCTE is the shared backward goal-expansion prefix used by both
// HoldsRole and HoldsRoleStanding. It expands (role, object) pairs via the
// role_grants rewrite rules (same_object + parent) into the `goals` relation and
// exposes a group-aware `user_groups` CTE. PostgreSQL requires the recursive
// reference to appear exactly once in the recursive term; multi-branch expansion
// is achieved with a LATERAL derived table (one reference to goals, three
// UNION ALL branches) UNIONed into the accumulator. Cycle-safe: goals are deduped
// via UNION, so the finite goal set terminates.
//
// The ONLY difference between HoldsRole and HoldsRoleStanding is the satisfaction
// SELECT appended after this prefix (bindings∪grants vs bindings-only) — the goal
// expansion itself is identical.
//
// SECURITY — KEEP IN SYNC: the three rewrite arms (same_object, parent-from-asset,
// parent-from-folder) are duplicated in ExplainRole below — keep the traversal
// semantics in sync (ExplainRole additionally emits via + path).
const holdsRoleGoalsCTE = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
goals(role_id, object_kind, object_id) AS (
    -- seed
    SELECT $2::uuid, $3::text, $4::uuid
  UNION
    -- one reference to goals; three expansion branches combined before the UNION
    SELECT ng.next_role_id, ng.next_kind, ng.next_object_id
    FROM goals g,
         LATERAL (
             -- same_object: (R,O) → (S,O)
             SELECT rg.source_role_id AS next_role_id,
                    g.object_kind    AS next_kind,
                    g.object_id      AS next_object_id
             FROM role_grants rg
             WHERE rg.role_id = g.role_id AND rg.via = 'same_object'

             UNION ALL

             -- parent on asset: (R,asset A) → (S, folder of A)
             SELECT rg.source_role_id,
                    'folder'::text,
                    a.folder_id
             FROM role_grants rg
             JOIN assets a ON g.object_kind = 'asset' AND a.id = g.object_id
             WHERE rg.role_id = g.role_id AND rg.via = 'parent'

             UNION ALL

             -- parent on folder: (R,folder F) → (S, parent folder)
             SELECT rg.source_role_id,
                    'folder'::text,
                    f.parent_id
             FROM role_grants rg
             JOIN folders f ON g.object_kind = 'folder' AND f.id = g.object_id
                            AND f.parent_id IS NOT NULL
             WHERE rg.role_id = g.role_id AND rg.via = 'parent'
         ) ng
)`

// holdsSatisfyBinding is the standing-binding satisfaction arm: a reached goal is
// satisfied by a direct/nested-group standing role_binding on it.
const holdsSatisfyBinding = `
    -- satisfaction via a standing role_binding on the reached goal.
    SELECT 1
    FROM goals g
    JOIN role_bindings rb ON rb.role_id = g.role_id
      AND ( (g.object_kind = 'asset'  AND rb.scope_asset_id  = g.object_id)
         OR (g.object_kind = 'folder' AND rb.scope_folder_id = g.object_id) )
      AND ( rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups) )
    -- a deactivated user holds nothing
    WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`

// holdsSatisfyGrant is the active-JIT-grant satisfaction arm (access membership
// only — NOT governance). SECURITY: mirror of the held-base grant arm (see
// heldCTE). now() enforces expiry/revocation at query time — no reaper required.
const holdsSatisfyGrant = `
    -- satisfaction via an active JIT access_grant (user-subject + asset-scope).
    SELECT 1
    FROM goals g
    JOIN access_grants ag ON ag.role_id = g.role_id
      AND g.object_kind = 'asset' AND ag.scope_asset_id = g.object_id
      AND ag.subject_user_id = $1 AND ag.revoked_at IS NULL AND ag.expires_at > now()
    -- a deactivated user holds nothing
    WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`

// HoldsRole reports whether userID holds roleID on the given object (objectKind is
// "asset" or "folder") — i.e. whether the user holds it via a standing role_binding
// OR an active JIT access_grant — resolving explicit role_grants rewrite rules
// (same_object + parent). Group-aware and cycle-safe. This is the ACCESS-membership
// predicate: a JIT-granted role counts. For the governance/eligibility predicate
// (grants excluded) use HoldsRoleStanding.
func (r *RoleResolver) HoldsRole(ctx context.Context, userID, roleID uuid.UUID, objectKind string, objectID uuid.UUID) (bool, error) {
	sql := holdsRoleGoalsCTE + `
SELECT EXISTS (` + holdsSatisfyBinding + `
  UNION ALL` + holdsSatisfyGrant + `
)`
	var ok bool
	if err := r.pool.QueryRow(ctx, sql, userID, roleID, objectKind, objectID).Scan(&ok); err != nil {
		return false, fmt.Errorf("holds role: %w", err)
	}
	return ok, nil
}

// HoldsRoleStanding reports whether userID holds roleID on the given object via a
// STANDING role_binding only (governance predicate — active JIT access_grants are
// EXCLUDED), resolving explicit role_grants rewrite rules (same_object + parent).
// Same signature/semantics as HoldsRole except the satisfaction base is
// role_bindings ONLY (the pre-T2 backward closure): a role obtained via a JIT
// grant gives real access (HoldsRole) but MUST NOT confer governance eligibility,
// so IsApprover/IsEligibleRequester resolve their role branch through THIS method.
func (r *RoleResolver) HoldsRoleStanding(ctx context.Context, userID, roleID uuid.UUID, objectKind string, objectID uuid.UUID) (bool, error) {
	sql := holdsRoleGoalsCTE + `
SELECT EXISTS (` + holdsSatisfyBinding + `
)`
	var ok bool
	if err := r.pool.QueryRow(ctx, sql, userID, roleID, objectKind, objectID).Scan(&ok); err != nil {
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
// given asset, resolving explicit role_grants rewrite rules (same_object +
// parent) down to standing bindings (direct or via nested groups). It mirrors
// HoldsRole's traversal (see the goals CTE above) but carries the chain as a
// jsonb path and uses an in-path cycle guard, so it reports "all the ways"
// rather than a single boolean. holds == (len(paths) > 0), which is equivalent
// to HoldsRole: the in-path guard only prevents revisiting a (role,object)
// tuple within one path, so it does not shrink the reachable-and-satisfied goal
// set; it merely bounds each path to distinct tuples, guaranteeing termination.
//
// Unknown-but-parseable userID/roleID/assetID simply match no goals or bindings
// and yield holds=false, paths=nil (no error): this is intentional for the
// admin/self introspection tool.
func (r *RoleResolver) ExplainRole(ctx context.Context, userID, roleID, assetID uuid.UUID) (bool, []ExplainPath, error) {
	const sql = `
WITH RECURSIVE
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
goals(role_id, object_kind, object_id, path) AS (
    SELECT $2::uuid, 'asset'::text, $3::uuid,
           jsonb_build_array(jsonb_build_object(
             'role_id', $2::uuid, 'object_kind', 'asset', 'object_id', $3::uuid, 'via', 'direct'))
  UNION ALL
    SELECT x.role_id, x.object_kind, x.object_id,
           g.path || jsonb_build_object('role_id', x.role_id, 'object_kind', x.object_kind, 'object_id', x.object_id, 'via', x.via)
    FROM goals g,
    LATERAL (
        -- The same three rewrite arms (same_object, parent-from-asset,
        -- parent-from-folder) are duplicated in HoldsRole above — keep the
        -- traversal semantics in sync (this variant additionally emits via + path).
        SELECT rg.source_role_id AS role_id, g.object_kind AS object_kind, g.object_id AS object_id, 'same_object'::text AS via
        FROM role_grants rg WHERE rg.role_id = g.role_id AND rg.via = 'same_object'
      UNION ALL
        SELECT rg.source_role_id, 'folder'::text, a.folder_id, 'parent'::text
        FROM role_grants rg JOIN assets a ON g.object_kind = 'asset' AND a.id = g.object_id
        WHERE rg.role_id = g.role_id AND rg.via = 'parent'
      UNION ALL
        SELECT rg.source_role_id, 'folder'::text, f.parent_id, 'parent'::text
        FROM role_grants rg JOIN folders f ON g.object_kind = 'folder' AND f.id = g.object_id AND f.parent_id IS NOT NULL
        WHERE rg.role_id = g.role_id AND rg.via = 'parent'
    ) x
    WHERE NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(g.path) e
        WHERE (e->>'role_id')::uuid = x.role_id
          AND e->>'object_kind' = x.object_kind
          AND (e->>'object_id')::uuid = x.object_id
    )
)
SELECT path, binding_id, subject_user_id, subject_group_id
FROM (
    -- satisfaction via a standing role_binding on the reached goal.
    SELECT g.path AS path, rb.id AS binding_id, rb.subject_user_id, rb.subject_group_id
    FROM goals g
    JOIN role_bindings rb ON rb.role_id = g.role_id
      AND ((g.object_kind = 'asset'  AND rb.scope_asset_id  = g.object_id)
        OR (g.object_kind = 'folder' AND rb.scope_folder_id = g.object_id))
      AND (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
    -- a deactivated user holds nothing
    WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)
  UNION ALL
    -- satisfaction via an active JIT access_grant (user-subject + asset-scope).
    -- SECURITY: mirror of the held-base grant arm (see heldCTE). The grant id
    -- stands in as binding_id and its user is the subject; now() enforces
    -- expiry/revocation at query time — no reaper required.
    SELECT g.path AS path, ag.id AS binding_id, ag.subject_user_id, NULL::uuid AS subject_group_id
    FROM goals g
    JOIN access_grants ag ON ag.role_id = g.role_id
      AND g.object_kind = 'asset' AND ag.scope_asset_id = g.object_id
      AND ag.subject_user_id = $1 AND ag.revoked_at IS NULL AND ag.expires_at > now()
    -- a deactivated user holds nothing
    WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)
) sat
-- Defensive cap: role_grants is tiny/admin-curated, but bound worst-case result
-- size. This caps explanation breadth only — holds (len(paths)>0) stays correct
-- because the cap is ≥ 1 and never empties a non-empty result.
LIMIT 500`

	rows, err := r.pool.Query(ctx, sql, userID, roleID, assetID)
	if err != nil {
		return false, nil, fmt.Errorf("explain role: %w", err)
	}
	defer rows.Close()

	var paths []ExplainPath
	for rows.Next() {
		var (
			pathRaw   []byte
			bindingID uuid.UUID
			subjUser  pgtype.UUID
			subjGroup pgtype.UUID
		)
		if err := rows.Scan(&pathRaw, &bindingID, &subjUser, &subjGroup); err != nil {
			return false, nil, fmt.Errorf("explain role scan: %w", err)
		}
		var rawSteps []explainStepJSON
		if err := json.Unmarshal(pathRaw, &rawSteps); err != nil {
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
		case subjUser.Valid:
			subject = "user:" + uuid.UUID(subjUser.Bytes).String()
		case subjGroup.Valid:
			subject = "group:" + uuid.UUID(subjGroup.Bytes).String()
		}
		paths = append(paths, ExplainPath{Steps: steps, BindingID: bindingID, Subject: subject})
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("explain role rows: %w", err)
	}
	return len(paths) > 0, paths, nil
}
