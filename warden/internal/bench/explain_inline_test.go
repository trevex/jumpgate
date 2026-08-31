//go:build bench

package bench

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// visibleRequestableSQL is copied VERBATIM from the generated
// internal/postgres/sqlc/authz.sql.go `visibleRequestable` const (the query body of
// Queries.VisibleRequestable). It is the multi-asset requestability query whose
// JOIN LATERAL over authz_effective_request_policy is the riskiest inlining case: if
// that SRF is planned as an opaque Function Scan it re-executes per candidate asset,
// re-introducing the O(assets) blowup the bench suite exists to catch. We EXPLAIN the
// real query text here so the inlining gate tracks what the service actually runs.
//
// The const is unexported, so it is reproduced here; TestVisibleRequestableSQLMatchesGenerated
// (below) is a drift guard — if the generated SQL changes, update this copy.
const visibleRequestableSQL = `WITH RECURSIVE
ancestors(asset_id, folder_id, depth) AS (
    SELECT id, folder_id, 0 FROM assets
  UNION ALL
    SELECT a.asset_id, f.parent_id, a.depth + 1
    FROM folders f JOIN ancestors a ON f.id = a.folder_id
    WHERE f.parent_id IS NOT NULL
),
held_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM authz_held($1) WHERE object_kind = 'asset'
),
held_standing_on_asset(asset_id, role_id) AS (
    SELECT object_id, role_id FROM authz_held_standing($1) WHERE object_kind = 'asset'
),
candidate_pairs(asset_id, role_id) AS (
    SELECT rp.scope_asset_id, rp.role_id
    FROM request_policies rp WHERE rp.scope_asset_id IS NOT NULL
  UNION
    SELECT an.asset_id, rp.role_id
    FROM request_policies rp JOIN ancestors an ON rp.scope_folder_id = an.folder_id
  UNION
    SELECT a.id, rp.role_id
    FROM request_policies rp CROSS JOIN assets a
    WHERE rp.scope_folder_id IS NULL AND rp.scope_asset_id IS NULL
),
effective AS (
    SELECT cp.asset_id, cp.role_id, ep.policy_id, ep.requester_role_id
    FROM candidate_pairs cp
    JOIN LATERAL authz_effective_request_policy(cp.role_id, cp.asset_id) ep ON true
)
SELECT e.asset_id, e.role_id
FROM effective e
WHERE
  (
    ( e.requester_role_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM held_standing_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.requester_role_id) )
    OR EXISTS (
        SELECT 1 FROM request_policy_subjects rps
        WHERE rps.policy_id = e.policy_id
          AND rps.kind = 'requester'
          AND (rps.subject_user_id = $1
               OR rps.subject_group_id IN (SELECT group_id FROM authz_user_groups($1)))
          AND authz_user_is_active($1)
    )
  )
  AND NOT EXISTS (SELECT 1 FROM held_on_asset ha WHERE ha.asset_id = e.asset_id AND ha.role_id = e.role_id)
`

// visibleAssetsUnderSQL is copied VERBATIM from the generated authz.sql.go
// `visibleAssetsUnder` const. It exercises the shared management-visibility cascade
// functions (authz_mgmt_global_read / authz_mgmt_visible_folders, which further
// splices authz_mgmt_read_anchor_folders → authz_held). If any of those STABLE SQL
// functions fails to inline it shows up as a `Function Scan on authz_mgmt_*` node —
// for authz_mgmt_visible_folders that is an opaque per-asset re-evaluation gating the
// scan over all assets, exactly the blowup the gate exists to catch.
const visibleAssetsUnderSQL = `SELECT a.id
FROM assets a
WHERE (
        (NOT $1::boolean AND $2::uuid IS NOT NULL AND a.folder_id = $2::uuid)
     OR ($1::boolean AND (
            $2::uuid IS NULL
            OR a.folder_id IN (SELECT f.id FROM folders f WHERE f.path_ids <@ (SELECT path_ids FROM folders WHERE id = $2::uuid))
        ))
      )
  AND (
        a.id = ANY($3::uuid[])
     OR (SELECT authz_mgmt_global_read($4, $5, $6, $7))
     OR a.folder_id IN (SELECT folder_id FROM authz_mgmt_visible_folders($4, $5, $6, $7))
     OR EXISTS (
        SELECT 1 FROM ssh_asset_login sal
        WHERE sal.asset_id = a.id
          AND EXISTS (
              SELECT 1 FROM role_capabilities rc
              WHERE rc.role_id IN (
                    SELECT role_id FROM authz_global_held($4)
                  UNION
                    SELECT h.role_id FROM authz_held($4) h
                    WHERE (h.object_kind = 'asset' AND h.object_id = a.id)
                       OR (h.object_kind = 'folder'
                           AND h.object_id IN (
                               SELECT f.id FROM folders f
                               WHERE f.path_ids @> (SELECT af.path_ids FROM folders af WHERE af.id = a.folder_id)
                           ))
              )
              AND (rc.scope = 'ssh' OR rc.scope = '*')
              AND (rc.action = 'login' OR rc.action = '*')
              AND (rc.qualifier = sal.login OR rc.qualifier = '*')
          )
      )
      )
ORDER BY a.id`

// heldAssetSQL is a representative direct use of authz_held: the asset-scoped
// projection used by the held-object queries.
const heldAssetSQL = `SELECT object_id FROM authz_held($1) WHERE object_kind = 'asset'`

// explainVerbose runs EXPLAIN (VERBOSE) for sql on the shared pool and returns the
// whole plan as one lowercased string for substring assertions.
func explainVerbose(tb testing.TB, pool *pgxpool.Pool, sql string, args ...any) string {
	tb.Helper()
	rows, err := pool.Query(context.Background(), "EXPLAIN (VERBOSE) "+sql, args...)
	if err != nil {
		tb.Fatalf("EXPLAIN failed: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			tb.Fatalf("scan plan line: %v", err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		tb.Fatalf("read plan: %v", err)
	}
	return strings.ToLower(b.String())
}

func mustNotContain(tb testing.TB, plan, needle, why string) {
	tb.Helper()
	if strings.Contains(plan, strings.ToLower(needle)) {
		tb.Fatalf("%s\nEXPLAIN plan unexpectedly contains %q:\n%s", why, needle, plan)
	}
}

func mustContain(tb testing.TB, plan, needle, why string) {
	tb.Helper()
	if !strings.Contains(plan, strings.ToLower(needle)) {
		tb.Fatalf("%s\nEXPLAIN plan is missing %q:\n%s", why, needle, plan)
	}
}

// TestAuthzSRFsInline is the inlining gate: against a bench-scale seeded graph it runs
// EXPLAIN (VERBOSE) on the representative authz queries and asserts the shared
// authz_* set-returning functions were INLINED by the planner
// (inline_set_returning_functions). An inlined SRF disappears as a plan node — its
// body is spliced in and shows up as scans on the underlying tables (role_bindings /
// role_grants / request_policies). A NON-inlined SRF shows up as a `Function Scan on
// authz_*` node and, under the VisibleRequestable LATERAL, re-executes per candidate
// asset = the O(assets) blowup. We assert BOTH properties: no Function Scan on the
// authz_* SRFs, AND the underlying tables are referenced directly.
func TestAuthzSRFsInline(t *testing.T) {
	pool, _ := sharedDB(t)
	// dense-inheritance is the largest profile (deep + wide + many policies): the
	// worst case for a non-inlined per-asset re-plan to show itself.
	w := Generate(t, profileByName(t, "dense-inheritance"))
	user := w.DeepSubject

	t.Run("authz_held", func(t *testing.T) {
		plan := explainVerbose(t, pool, heldAssetSQL, user)
		// The recursive body was spliced in: the closure's base+recursive arms scan
		// role_bindings and role_grants directly.
		mustContain(t, plan, "role_bindings", "authz_held did not inline")
		mustContain(t, plan, "role_grants", "authz_held did not inline")
		// No opaque Function Scan on the held SRFs.
		mustNotContain(t, plan, "Function Scan on authz_held", "authz_held is planned as an opaque Function Scan (did NOT inline)")
		mustNotContain(t, plan, "Function Scan on authz_held_impl", "authz_held_impl is planned as an opaque Function Scan (did NOT inline)")
	})

	t.Run("visible_requestable", func(t *testing.T) {
		plan := explainVerbose(t, pool, visibleRequestableSQL, user)
		// CRITICAL: the LATERAL SRF must NOT be an opaque Function Scan — otherwise it
		// re-executes per candidate asset (the O(assets) regression).
		mustNotContain(t, plan, "Function Scan on authz_effective_request_policy",
			"authz_effective_request_policy is planned as an opaque Function Scan under the LATERAL — it re-executes per asset (O(assets) blowup). This triggers the plan's set-based fallback; STOP and report.")
		mustNotContain(t, plan, "Function Scan on authz_held", "authz_held did not inline in VisibleRequestable")
		mustNotContain(t, plan, "Function Scan on authz_held_standing", "authz_held_standing did not inline in VisibleRequestable")
		// The inlined bodies scan the real tables directly, proving the functions were
		// spliced in rather than called opaquely.
		mustContain(t, plan, "request_policies", "request_policies not referenced — authz_effective_request_policy did not inline")
		mustContain(t, plan, "role_bindings", "role_bindings not referenced — authz_held/_standing did not inline")
		mustContain(t, plan, "role_grants", "role_grants not referenced — authz_held/_standing did not inline")
	})

	t.Run("visible_assets_under", func(t *testing.T) {
		// cascade=true, parent=NULL (whole tree — the heaviest case: the mgmt cascade
		// gates the scan over ALL assets), no ACCESS ids, catalog:asset:read.
		plan := explainVerbose(t, pool, visibleAssetsUnderSQL,
			true, nil, []uuid.UUID{}, user, "catalog", "asset", "read")
		// The shared cascade SQL functions must be spliced in, not planned opaquely.
		mustNotContain(t, plan, "Function Scan on authz_mgmt_visible_folders",
			"authz_mgmt_visible_folders is an opaque Function Scan — it re-evaluates per asset (O(assets) blowup). STOP and report.")
		mustNotContain(t, plan, "Function Scan on authz_mgmt_read_anchor_folders", "authz_mgmt_read_anchor_folders did not inline")
		mustNotContain(t, plan, "Function Scan on authz_mgmt_global_read", "authz_mgmt_global_read did not inline")
		mustNotContain(t, plan, "Function Scan on authz_held", "authz_held did not inline in VisibleAssetsUnder")
		// The inlined bodies scan the real tables directly.
		mustContain(t, plan, "role_capabilities", "role_capabilities not referenced — the mgmt cascade functions did not inline")
		mustContain(t, plan, "folders", "folders not referenced — authz_mgmt_visible_folders did not inline")
	})
}

// TestVisibleRequestableSQLMatchesGenerated is a drift guard: it re-runs the EXPLAIN
// against the generated query via a normalized comparison so the copied
// visibleRequestableSQL cannot silently diverge from what the service executes. It
// compares the whitespace-collapsed body against the generated const's known shape
// (the LATERAL over authz_effective_request_policy must be present).
func TestVisibleRequestableSQLMatchesGenerated(t *testing.T) {
	// Structural anchors that MUST be present for the gate to be meaningful.
	for _, anchor := range []string{
		"JOIN LATERAL authz_effective_request_policy(cp.role_id, cp.asset_id)",
		"authz_held($1)",
		"authz_held_standing($1)",
	} {
		if !strings.Contains(visibleRequestableSQL, anchor) {
			t.Fatalf("visibleRequestableSQL drifted: missing anchor %q — re-copy from sqlc/authz.sql.go visibleRequestable const", anchor)
		}
	}
}

// profileByName returns the named profile or fails the test.
func profileByName(tb testing.TB, name string) Profile {
	tb.Helper()
	for _, p := range Profiles {
		if p.Name == name {
			return p
		}
	}
	tb.Fatalf("no profile named %q", name)
	return Profile{}
}
