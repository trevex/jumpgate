package authz

// Guards for the SINGLE-SOURCED held-closure recursive CTEs.
//
// The forward "held" closure (role membership through the role_grants rewrite
// graph) is no longer hand-copied: every held / held_standing closure is
// COMPOSED from the shared string fragments in heldclosure.go
//
//   - cteUserGroups   — the recursive group-membership CTE.
//   - cteStandingBase — the standing role_bindings base arm.
//   - cteGrantArm     — the active-JIT-grant base arm (held ONLY).
//   - cteRewriteArms  — the three-arm role_grants rewrite LATERAL block.
//   - heldClosureSQL(name, withGrants) — assembles a closure from the fragments.
//
// via heldCTEPrefix (heldCTE, sql_authorizer.go) and requestableClosuresPrefix
// (requestableRolesCTE + visibleRequestableCTE, requestable.go). Because the
// closure body has exactly ONE source, Requestable-tier eligibility cannot
// silently diverge from Check's grant decision — the historical
// hand-copy-drift bug is now impossible by construction.
//
// These tests defend that property from two angles:
//
//  1. COMPOSITION — every composed query const must actually contain the shared
//     fragments (once per embedded closure). A future edit that bypasses the
//     builder and inlines a bespoke closure would drop a fragment and go red.
//
//  2. GRANT-ARM INVARIANT — the standing-only `held_standing` closure must NEVER
//     carry the grant arm (a JIT grant confers access but NOT governance/request
//     eligibility). This is enforced STRUCTURALLY by heldClosureSQL omitting
//     cteGrantArm when withGrants == false; the tests pin that structure.

import (
	"regexp"
	"strings"
	"testing"
)

var (
	lineCommentRe = regexp.MustCompile(`--[^\n]*`)
	wsRe          = regexp.MustCompile(`\s+`)
)

// normalizeSQL strips SQL line-comments and collapses all whitespace runs to a
// single space, so comparisons key on SQL body — indentation and documentary
// `-- comments` are ignored.
func normalizeSQL(s string) string {
	s = lineCommentRe.ReplaceAllString(s, "")
	s = wsRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// countNorm returns how many times the normalized fragment occurs in the
// normalized haystack.
func countNorm(haystack, fragment string) int {
	return strings.Count(normalizeSQL(haystack), normalizeSQL(fragment))
}

// containsNorm reports whether the normalized fragment is a substring of the
// normalized haystack.
func containsNorm(haystack, fragment string) bool {
	return strings.Contains(normalizeSQL(haystack), normalizeSQL(fragment))
}

const bypassHint = "A composed held-closure query no longer draws its closure " +
	"body from the shared fragments in heldclosure.go (cteUserGroups / " +
	"cteStandingBase / cteGrantArm / cteRewriteArms via heldClosureSQL). If you " +
	"inlined a bespoke closure you have reintroduced the copy-paste-drift risk " +
	"this refactor removed — compose from heldClosureSQL instead."

// composedConst names one of the query consts built from the shared fragments,
// with the expected per-const occurrence count of each shared fragment.
//
// A const may embed MORE THAN ONE forward-closure (each requestable const embeds
// both a `held` and a `held_standing`), and the rewrite arms + standing base
// appear once PER CLOSURE. Counting (not mere containment) catches divergence in
// one of two closures.
//
//   - wantClosures   : rewrite-arm block AND standing base arm count (one each
//     per forward-closure).
//   - wantUserGroups : the user_groups CTE is a single top-level CTE per const → 1.
//   - wantGrantArms  : active-grant base arm — one per `held` closure; a
//     `held_standing` closure never carries it → 1 everywhere.
type composedConst struct {
	name           string
	sql            string
	wantClosures   int
	wantUserGroups int
	wantGrantArms  int
}

func composedConsts() []composedConst {
	return []composedConst{
		{
			name: "heldCTE (internal/authz/sql_authorizer.go)",
			sql:  heldCTE, wantClosures: 1, wantUserGroups: 1, wantGrantArms: 1,
		},
		{
			name: "requestableRolesCTE (internal/authz/requestable.go)",
			sql:  requestableRolesCTE, wantClosures: 2, wantUserGroups: 1, wantGrantArms: 1,
		},
		{
			name: "visibleRequestableCTE (internal/authz/requestable.go)",
			sql:  visibleRequestableCTE, wantClosures: 2, wantUserGroups: 1, wantGrantArms: 1,
		},
	}
}

// TestComposedFromSharedFragments asserts every query const carries the shared
// user_groups CTE, the three-arm role_grants rewrite block, and the
// standing-binding base arm — with the EXACT per-const occurrence count (once
// per embedded closure for the arms, once for the top-level user_groups CTE).
// This catches a future edit that bypasses heldClosureSQL and hand-inlines a
// closure that omits (or subtly alters) a shared fragment.
func TestComposedFromSharedFragments(t *testing.T) {
	for _, c := range composedConsts() {
		fragments := []struct {
			what     string
			fragment string
			want     int
		}{
			{"user_groups recursive CTE (cteUserGroups)", cteUserGroups, c.wantUserGroups},
			{"three-arm role_grants rewrite block (cteRewriteArms)", cteRewriteArms, c.wantClosures},
			{"standing role_bindings base arm (cteStandingBase)", cteStandingBase, c.wantClosures},
		}
		for _, f := range fragments {
			if got := countNorm(c.sql, f.fragment); got != f.want {
				t.Errorf("%s carries the shared %s %d time(s), want %d.\n%s",
					c.name, f.what, got, f.want, bypassHint)
			}
		}
	}
}

// TestComposedGrantArmCount asserts the active-grant base arm appears EXACTLY
// once per const: carried by each `held` closure and NEVER by a `held_standing`
// closure. A grant arm leaking into a held_standing closure would let a JIT
// grant confer request-eligibility (governance) — a security-critical bug.
func TestComposedGrantArmCount(t *testing.T) {
	for _, c := range composedConsts() {
		got := countNorm(c.sql, cteGrantArm)
		if got != c.wantGrantArms {
			t.Errorf("%s carries the active-grant base arm (cteGrantArm) %d time(s), want %d "+
				"(one per `held` closure; a `held_standing` closure must NEVER carry it).\n%s",
				c.name, got, c.wantGrantArms, bypassHint)
		}
	}
}

// TestHeldClosureBuilderGrantArm pins the grant-arm invariant at its structural
// source: heldClosureSQL(withGrants=true) MUST contain the grant arm and
// heldClosureSQL(withGrants=false) MUST NOT. Both variants must always carry the
// shared standing base and rewrite arms. This is the guarantee that makes
// "held_standing has no grant arm" impossible to get wrong: the builder simply
// omits cteGrantArm when withGrants is false, so no reviewer vigilance is needed.
func TestHeldClosureBuilderGrantArm(t *testing.T) {
	withGrants := heldClosureSQL("held", true)
	standingOnly := heldClosureSQL("held_standing", false)

	if !containsNorm(withGrants, cteGrantArm) {
		t.Errorf("heldClosureSQL(withGrants=true) is missing the grant arm — the `held` closure must carry it.")
	}
	if containsNorm(standingOnly, cteGrantArm) {
		t.Errorf("heldClosureSQL(withGrants=false) contains the grant arm — a `held_standing` closure must NEVER carry it (a JIT grant would wrongly confer request-eligibility).")
	}
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"held (withGrants=true)", withGrants},
		{"held_standing (withGrants=false)", standingOnly},
	} {
		if !containsNorm(tc.sql, cteStandingBase) {
			t.Errorf("%s is missing the shared standing base arm.", tc.name)
		}
		if !containsNorm(tc.sql, cteRewriteArms) {
			t.Errorf("%s is missing the shared rewrite arms.", tc.name)
		}
		// The recursive arm must alias the closure by its own name so cteRewriteArms'
		// `h` reference resolves; a name-substitution bug would break the recursion.
		if tc.name[:4] == "held" && !strings.Contains(tc.sql, "FROM held") {
			t.Errorf("%s recursive arm does not reference the closure by name.", tc.name)
		}
	}
}

// TestHeldStandingHasNoGrantArm pins the held_standing invariant on the actual
// composed query consts: the standing-only closure embedded in each requestable
// const must NOT contain the grant arm, but must still carry the shared rewrite
// arms and standing base (proving it is a real, correctly-composed closure).
func TestHeldStandingHasNoGrantArm(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"requestableRolesCTE (internal/authz/requestable.go)", requestableRolesCTE},
		{"visibleRequestableCTE (internal/authz/requestable.go)", visibleRequestableCTE},
	}
	for _, c := range cases {
		body, ok := heldStandingBody(c.sql)
		if !ok {
			t.Fatalf("%s: could not locate the held_standing(...) closure body — "+
				"the closure was renamed or removed.\n%s", c.name, bypassHint)
		}
		if containsNorm(body, cteGrantArm) {
			t.Errorf("%s: the held_standing closure carries the active-grant base "+
				"arm — a JIT grant would wrongly confer request-eligibility.\n%s", c.name, bypassHint)
		}
		if !containsNorm(body, cteRewriteArms) {
			t.Errorf("%s: extracted held_standing body is missing the rewrite arms — "+
				"extraction is wrong or the closure diverged.\n%s", c.name, bypassHint)
		}
		if !containsNorm(body, cteStandingBase) {
			t.Errorf("%s: extracted held_standing body is missing the standing base arm.\n%s",
				c.name, bypassHint)
		}
	}
}

// heldStandingBody returns the SQL from `held_standing(...) AS (` up to the next
// top-level `),\n` that closes the CTE definition. Returns false if the closure
// is not present.
func heldStandingBody(sql string) (string, bool) {
	const marker = "held_standing(role_id, object_kind, object_id) AS ("
	i := strings.Index(sql, marker)
	if i < 0 {
		return "", false
	}
	rest := sql[i+len(marker):]
	// The closure body ends at the LATERAL subquery's `) x` followed by the
	// CTE-closing `)`. Anchor on the unique closing sequence `) x\n)`.
	end := strings.Index(rest, ") x\n)")
	if end < 0 {
		return "", false
	}
	return rest[:end+len(") x\n)")], true
}
