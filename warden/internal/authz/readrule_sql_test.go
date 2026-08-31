package authz

import (
	"context"
	"testing"
)

// readRuleSQL mirrors the read-broadening arm inside authz_mgmt_read_anchor_folders:
// a held (scope,action,qualifier) row satisfies READ of an object whose own read cap
// normalizes to ($4,$5,$6) when it matches that triple OR the catalog:folder:read
// triple. This pins the SQL rule against Go ReadAllowed so the two cannot drift.
const readRuleSQL = `
SELECT
  ((($1 = $4 OR $1 = '*') AND ($2 = $5 OR $2 = '*') AND ($3 = $6 OR $3 = '*'))
   OR (($1 = 'catalog' OR $1 = '*') AND ($2 = 'folder' OR $2 = '*') AND ($3 = 'read' OR $3 = '*')))`

func TestReadAllowedMatchesSQL(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// Held single-capability patterns to probe (the row the user actually holds).
	held := []string{
		"catalog:asset:read", "catalog:folder:read", "access:role:read",
		"identity:group:read", "catalog:**", "**", "catalog:folder:*",
		"ssh:login:root", "catalog:asset:create",
	}
	// Object read caps to test each held pattern against.
	objectReadCaps := []string{
		"catalog:asset:read", "access:role:read", "identity:group:read",
	}

	for _, h := range held {
		hs, ha, hq := NormalizeCap(h)
		for _, obj := range objectReadCaps {
			oscope, oa, oq := NormalizeCap(obj)
			var sqlGot bool
			if err := pool.QueryRow(ctx, readRuleSQL, hs, ha, hq, oscope, oa, oq).Scan(&sqlGot); err != nil {
				t.Fatalf("query (held=%q obj=%q): %v", h, obj, err)
			}
			goGot := Capabilities{h}.ReadAllowed(obj)
			if sqlGot != goGot {
				t.Errorf("held=%q obj=%q: SQL=%v Go=%v", h, obj, sqlGot, goGot)
			}
		}
	}
}
