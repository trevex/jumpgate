package authz

import "fmt"

// SINGLE SOURCE OF TRUTH for the held-closure recursive-CTE SQL.
//
// The forward "held" closure — the (role, object) pairs a user holds through
// the role_grants rewrite graph — is security-critical: Check's grant decision
// (heldCTE, sql_authorizer.go) and the Requestable-tier eligibility
// (requestableRolesCTE / visibleRequestableCTE, requestable.go) MUST resolve
// membership identically, or a role is offered/withheld inconsistently.
//
// Rather than hand-copy the SQL across those queries (which is impossible to
// keep in sync by inspection), every held / held_standing closure is COMPOSED
// from the shared string fragments below. The shared logic therefore exists
// exactly once. Each query still wraps the composed closure in its own trailing
// SELECT/CTEs; only the DUPLICATED closure body is centralized here.
//
// The reviewer's model:
//
//	held          = user_groups + standing_base + grant_arm + rewrite_arms
//	held_standing = user_groups + standing_base +             rewrite_arms
//
// A `held_standing` closure MUST NEVER carry the grant arm (a JIT grant confers
// access but not governance/request eligibility). That invariant is STRUCTURAL:
// heldClosureSQL simply omits cteGrantArm when withGrants == false.
//
// Parameter placeholders: every fragment binds ONLY the user id ($1). Callers
// are free to use $2, $3, … in their own trailing SELECT/CTEs.

// cteUserGroups is the recursive group-membership CTE (group-aware, cycle-safe).
// It is a single top-level CTE — emit it once per WITH RECURSIVE, before the
// held closures. Trailing comma so it can be followed by the closure CTEs.
const cteUserGroups = `
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),`

// cteStandingBase is the standing role_bindings base arm — the base every
// held-style closure shares (direct or nested-group binding; deactivated user
// holds nothing).
const cteStandingBase = `
    -- base: direct standing bindings for the user or a (nested) group
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))
      -- a deactivated user holds nothing
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`

// cteGrantArm is the active-JIT-grant base arm carried ONLY by `held` closures
// (never by `held_standing`). now() enforces expiry/revocation at query time —
// an expired/revoked grant stops conferring immediately, no reaper required.
const cteGrantArm = `
    -- base: active JIT access_grants (user-subject + asset-scope). A JIT grant
    -- confers access (held) but NOT governance (held_standing omits this arm).
    SELECT g.role_id, 'asset'::text, g.scope_asset_id
    FROM access_grants g
    WHERE g.subject_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > now()
      -- a deactivated user holds nothing
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.deactivated_at IS NULL)`

// cteRewriteArms is the three-arm role_grants rewrite LATERAL block (same_object
// + parent→child-folders + parent→child-assets). PostgreSQL permits the
// recursive self-reference exactly once, so the branches are combined via a
// LATERAL subquery referencing the current row `h` (the enclosing recursive arm
// aliases the closure as `h`). Cycle-safe: UNION dedup over the finite
// roles × objects set terminates without a depth column.
const cteRewriteArms = `
    LATERAL (
        -- same_object: hold S on O + rule (R ⊇ S same_object) ⇒ hold R on O
        SELECT rg.role_id, h.object_kind, h.object_id
        FROM role_grants rg
        WHERE rg.source_role_id = h.role_id AND rg.via = 'same_object'
      UNION ALL
        -- parent → child folders of folder O
        SELECT rg.role_id, 'folder'::text, cf.id
        FROM role_grants rg
        JOIN folders cf ON h.object_kind = 'folder' AND cf.parent_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
      UNION ALL
        -- parent → child assets directly in folder O
        SELECT rg.role_id, 'asset'::text, ca.id
        FROM role_grants rg
        JOIN assets ca ON h.object_kind = 'folder' AND ca.folder_id = h.object_id
        WHERE rg.source_role_id = h.role_id AND rg.via = 'parent'
    ) x`

// heldClosureSQL composes one held-style recursive CTE definition:
//
//	<name>(role_id, object_kind, object_id) AS (
//	    <standing base>
//	  [UNION <grant arm>]        -- only when withGrants
//	  UNION
//	    <recursive rewrite arm over `<name> h`>
//	)
//
// The recursive arm aliases the closure as `h`, which cteRewriteArms references;
// the name is substituted so the SAME rewrite/base fragments serve both the
// grant-augmented `held` closure and the standing-only `held_standing` closure.
// Omitting cteGrantArm when withGrants == false makes the "held_standing has no
// grant arm" invariant structural rather than review-enforced.
//
// The returned block ends WITHOUT a trailing comma or `)` terminator beyond its
// own closing paren, so callers concatenate closures with `,\n` and follow with
// their own CTEs.
func heldClosureSQL(name string, withGrants bool) string {
	grant := ""
	if withGrants {
		grant = `
  UNION` + cteGrantArm
	}
	return fmt.Sprintf(`%s(role_id, object_kind, object_id) AS (%s%s
  UNION
    SELECT x.role_id, x.object_kind, x.object_id
    FROM %s h,%s
)`, name, cteStandingBase, grant, name, cteRewriteArms)
}

// heldCTEPrefix is the shared `WITH RECURSIVE user_groups(...), held(...)` prefix
// used by sql_authorizer.go's Active-tier queries. It composes the user_groups
// CTE and the grant-augmented `held` closure; callers append their own trailing
// SELECT (which may reference $2, $3, …).
var heldCTEPrefix = "\nWITH RECURSIVE\n" + cteUserGroups[1:] + "\n" +
	heldClosureSQL("held", true)

// StandingHeldClosurePrefix returns the `WITH RECURSIVE user_groups(...),
// held_standing(...)` prefix: the caller's transitive group closure plus the
// STANDING-ONLY forward held closure (no JIT grants), binding $1 = user. It is
// exported so other packages can resolve standing governance eligibility over a
// SET of objects in one query — the caller's groups feed explicit-subject checks
// (request_policy_subjects) and held_standing(role_id, object_kind, object_id) feeds
// the approver/requester-role arm (equivalent to HoldsRoleStanding, which the
// requestable closures already rely on). Single-sourced from the same fragments as
// Check / HoldsRoleStanding, so it cannot drift. Callers append their own CTEs with
// a leading comma and a trailing SELECT.
func StandingHeldClosurePrefix() string {
	return "\nWITH RECURSIVE\n" + cteUserGroups[1:] + "\n" +
		heldClosureSQL("held_standing", false)
}

// requestableClosuresPrefix is the shared `WITH RECURSIVE user_groups(...),
// held(...), held_standing(...)` prefix for requestable.go. It carries BOTH the
// grant-augmented `held` closure (for active-exclusion) and the standing-only
// `held_standing` closure (for the requester predicate) — the same fragments as
// heldCTEPrefix, so the closures cannot diverge from Check. Callers append the
// remaining per-query CTEs (held_on_asset, ancestors, candidates, …) with a
// leading `,` and the final SELECT.
var requestableClosuresPrefix = "\nWITH RECURSIVE\n" + cteUserGroups[1:] + "\n" +
	// grant-augmented closure (base = bindings ∪ active grants) → active-exclusion.
	heldClosureSQL("held", true) + ",\n" +
	// standing-only closure (base = bindings ONLY, no grant arm) → requester predicate.
	heldClosureSQL("held_standing", false)
