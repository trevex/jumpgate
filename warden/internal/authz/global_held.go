package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// globalHeldCTE is the SCOPELESS analogue of heldCTE (sql_authorizer.go): it
// computes every role a user ($1) holds GLOBALLY — i.e. via a scopeless standing
// role_binding (scope_folder_id IS NULL AND scope_asset_id IS NULL) for the user
// or a (nested) group, closed over the role_grants rewrite graph.
//
// It faithfully mirrors heldCTE's security-critical arms, dropping the object
// dimension:
//
//   - The `user_groups` recursive CTE is the SHARED cteUserGroups fragment
//     (heldclosure.go) — the same one heldCTE / requestable.go compose from.
//   - The base arm is the standing role_bindings arm with heldCTE's deactivation
//     guard (a deactivated user holds nothing), but the object predicate is
//     REPLACED by the scopeless predicate `scope_folder_id IS NULL AND
//     scope_asset_id IS NULL`, and the object dimension is dropped. There is NO
//     active-grant arm: JIT access_grants are always asset-scoped, so they can
//     never confer a GLOBAL (scopeless) role. (This closure therefore does NOT
//     reuse cteStandingBase/cteRewriteArms — its base and recursion genuinely
//     differ from the object-dimensioned held closure.)
//   - The role_grants closure applies BOTH `via='same_object'` AND `via='parent'`:
//     with no object dimension there is no folder/asset to descend into, so a
//     global role simply confers every role reachable through EITHER rewrite arm.
//     (heldCTE's parent arms exist only to walk objects downward; globally they
//     collapse to "reachable role", so both arms are a plain source→target edge.)
//
// Termination is by UNION dedup over the finite role set (no depth column needed),
// exactly as in heldCTE. The final relation is `global_held(role_id)`.
var globalHeldCTE = "\nWITH RECURSIVE\n" + cteUserGroups[1:] + `
global_held(role_id) AS (
    -- base: scopeless standing bindings for the user or a (nested) group.
    SELECT rb.role_id
    FROM role_bindings rb
    WHERE rb.scope_folder_id IS NULL AND rb.scope_asset_id IS NULL
      AND (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
      -- a deactivated user holds nothing
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)
  UNION
    -- closure: role_grants confers globally through BOTH rewrite arms (no object
    -- dimension → same_object and parent both collapse to a source→target edge).
    SELECT rg.role_id
    FROM global_held gh
    JOIN role_grants rg ON rg.source_role_id = gh.role_id
    WHERE rg.via IN ('same_object', 'parent')
)`

// globalHeldCapabilities returns the capability patterns the user holds GLOBALLY
// via scopeless standing bindings closed over role_grants (see globalHeldCTE).
func (s *sqlAuthorizer) globalHeldCapabilities(ctx context.Context, userID uuid.UUID) (Capabilities, error) {
	rows, err := s.pool.Query(ctx, globalHeldCTE+`
SELECT DISTINCT rc.scope, rc.action, rc.qualifier FROM global_held gh JOIN role_capabilities rc ON rc.role_id = gh.role_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("global held: %w", err)
	}
	defer rows.Close()
	return scanCapabilities(rows)
}
