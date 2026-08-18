package authz

// Drift-guard for the DUPLICATED held-closure recursive CTEs.
//
// The forward "held" closure (role membership through the role_grants rewrite
// graph) is hand-copied as unexported const SQL in three places:
//
//   - heldCTE               (sql_authorizer.go)   — powers Check / VisibleAssets /
//                                                    RolesOnAsset (Active tier).
//   - requestableRolesCTE   (requestable.go)      — Requestable-tier eligibility
//                                                    for one asset.
//   - visibleRequestableCTE (requestable.go)      — Requestable-tier across all
//                                                    assets.
//
// Across those consts live FIVE forward-closures: one `held` in heldCTE, plus a
// `held` (grant-augmented) and a `held_standing` (standing-only) in each of the
// two requestable consts. Every one of the five MUST share the SAME user_groups
// recursive CTE, the SAME three-arm role_grants rewrite block (same_object +
// two parent arms), and the SAME standing-binding base arm — otherwise the
// Requestable-tier eligibility silently diverges from Check's grant decision,
// which is a security-critical bug (a role offered/withheld inconsistently).
//
// The `held` closures ADDITIONALLY carry the active-grant base arm; the
// `held_standing` closures MUST NOT (a JIT grant confers access but not
// governance/request eligibility).
//
// This test pins today's reviewed-correct SQL: the canonical fragments below are
// copied verbatim from heldCTE. If a future edit changes one copy without the
// others, this test goes red and points at the invariant. An INTENTIONAL change
// to a shared arm must update BOTH every code copy AND the canonical fragment
// here — that is the point: it forces a conscious, all-copies update.
//
// NOTE: heldCTE's rewrite block carries explanatory `-- comments` that the
// requestable copies omit. Those comments are documentation, not semantics, so
// the comparison normalizes SQL line-comments and whitespace away and asserts
// the SQL BODY is identical.

import (
	"regexp"
	"strings"
	"testing"
)

// canonicalUserGroups is the recursive user_groups CTE body — copied verbatim
// from heldCTE (sql_authorizer.go). Must appear in all five closures' consts.
const canonicalUserGroups = `
user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN user_groups ug ON gm.member_group_id = ug.group_id
),`

// canonicalRewriteArms is the three-arm role_grants rewrite LATERAL block
// (same_object + parent→folders + parent→assets) — copied verbatim from heldCTE
// (sql_authorizer.go), comments included. Normalization strips the comments so
// the requestable copies (which omit them) still match on SQL body.
const canonicalRewriteArms = `
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

// canonicalStandingBase is the standing role_bindings base arm — the base every
// held-style closure shares. Copied verbatim from heldCTE (sql_authorizer.go).
const canonicalStandingBase = `
    SELECT rb.role_id,
           (CASE WHEN rb.scope_asset_id IS NOT NULL THEN 'asset' ELSE 'folder' END)::text,
           COALESCE(rb.scope_asset_id, rb.scope_folder_id)
    FROM role_bindings rb
    WHERE (rb.subject_user_id = $1 OR rb.subject_group_id IN (SELECT group_id FROM user_groups))`

// canonicalGrantArm is the active-grant base arm carried ONLY by the `held`
// closures (never by `held_standing`). Copied verbatim from heldCTE
// (sql_authorizer.go), comments included (normalized away for comparison).
const canonicalGrantArm = `
    -- base: active JIT access_grants (user-subject + asset-scope). SECURITY —
    -- KEEP THIS ARM IDENTICAL across all held-style copies (requestable.go).
    SELECT g.role_id, 'asset'::text, g.scope_asset_id
    FROM access_grants g
    WHERE g.subject_user_id = $1 AND g.revoked_at IS NULL AND g.expires_at > now()`

var (
	lineCommentRe = regexp.MustCompile(`--[^\n]*`)
	wsRe          = regexp.MustCompile(`\s+`)
)

// normalizeSQL strips SQL line-comments and collapses all whitespace runs to a
// single space, so comparisons key on SQL body — indentation and documentary
// `-- comments` (which legitimately differ between copies) are ignored.
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

// heldConst names one of the duplicated CTE consts under test, with the exact
// occurrence counts each shared fragment must have in it.
//
// A const may embed MORE THAN ONE forward-closure (each requestable const embeds
// both a `held` and a `held_standing`), and the shared rewrite arms + standing
// base arm appear once PER CLOSURE. Counting (not mere containment) is essential:
// containment would pass even if ONE of two closures diverged, because the other,
// pristine closure still supplies a matching fragment. So we pin exact counts.
//
//   - wantClosures    : rewrite-arm block AND standing base arm count (one each
//     per forward-closure in the const).
//   - wantUserGroups  : the user_groups CTE is a single top-level CTE per const → 1.
//   - wantGrantArms   : active-grant base arm — one per `held` closure, and a
//     `held_standing` closure never carries it. heldCTE has one
//     `held`; each requestable const has one `held` (+ one
//     `held_standing`) → 1 everywhere.
type heldConst struct {
	name           string
	sql            string
	wantClosures   int
	wantUserGroups int
	wantGrantArms  int
}

func heldConsts() []heldConst {
	return []heldConst{
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

const resyncHint = "The duplicated held-closure CTE copies have DIVERGED. Re-sync " +
	"heldCTE (internal/authz/sql_authorizer.go), requestableRolesCTE and " +
	"visibleRequestableCTE (internal/authz/requestable.go) so every held / " +
	"held_standing closure shares the same user_groups CTE, rewrite arms, and " +
	"standing base. If the change was INTENTIONAL, update the canonical fragment " +
	"in heldclosure_sync_test.go too (which forces updating ALL copies)."

// TestHeldClosureSharedFragments asserts every duplicated const carries the
// shared user_groups CTE, the three-arm role_grants rewrite block, and the
// standing-binding base arm — with the EXACT per-const occurrence count (once
// per embedded closure for the arms, once for the top-level user_groups CTE).
// Divergence here splits Requestable eligibility from Check — a security-critical
// bug. Counting (not containment) catches divergence in one of two closures.
func TestHeldClosureSharedFragments(t *testing.T) {
	for _, c := range heldConsts() {
		fragments := []struct {
			what     string
			fragment string
			want     int
		}{
			{"user_groups recursive CTE", canonicalUserGroups, c.wantUserGroups},
			{"three-arm role_grants rewrite block (same_object + two parent arms)", canonicalRewriteArms, c.wantClosures},
			{"standing role_bindings base arm", canonicalStandingBase, c.wantClosures},
		}
		for _, f := range fragments {
			if got := countNorm(c.sql, f.fragment); got != f.want {
				t.Errorf("%s carries the canonical %s %d time(s), want %d.\n%s",
					c.name, f.what, got, f.want, resyncHint)
			}
		}
	}
}

// TestHeldClosureGrantArmInvariant asserts the active-grant base arm appears
// EXACTLY once per const: carried by each `held` closure and NEVER by a
// `held_standing` closure. heldCTE has one held closure; each requestable const
// has one `held` (+ one `held_standing`), so the count is one everywhere. A
// grant arm leaking into a held_standing closure would let a JIT grant confer
// request-eligibility (governance) — a security-critical bug.
func TestHeldClosureGrantArmInvariant(t *testing.T) {
	for _, c := range heldConsts() {
		got := countNorm(c.sql, canonicalGrantArm)
		if got != c.wantGrantArms {
			t.Errorf("%s carries the active-grant base arm %d time(s), want %d "+
				"(one per `held` closure; a `held_standing` closure must NEVER carry it).\n%s",
				c.name, got, c.wantGrantArms, resyncHint)
		}
	}
}

// TestHeldStandingHasNoGrantArm pins the held_standing invariant directly: the
// standing-only closures in the requestable consts must NOT contain the grant
// arm. Extract each held_standing(...) body and assert absence.
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
				"the closure was renamed or removed.\n%s", c.name, resyncHint)
		}
		if containsNorm(body, canonicalGrantArm) {
			t.Errorf("%s: the held_standing closure carries the active-grant base "+
				"arm — a JIT grant would wrongly confer request-eligibility.\n%s", c.name, resyncHint)
		}
		// Sanity: held_standing must still carry the shared rewrite arms and
		// standing base (i.e. it's a real closure, not an empty match).
		if !containsNorm(body, canonicalRewriteArms) {
			t.Errorf("%s: extracted held_standing body is missing the rewrite arms — "+
				"extraction is wrong or the closure diverged.\n%s", c.name, resyncHint)
		}
		if !containsNorm(body, canonicalStandingBase) {
			t.Errorf("%s: extracted held_standing body is missing the standing base arm.\n%s",
				c.name, resyncHint)
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
