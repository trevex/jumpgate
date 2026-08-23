package authz

import (
	"context"
	"testing"
)

var diffPatterns = []string{
	"**", "catalog:**", "ssh:**", "db:**", "k8s:*",
	"catalog:asset:*", "ssh:login:*", "k8s:*:*",
	"catalog:asset:read", "access:role:create", "identity:group:add-member",
	"ssh:login:deploy", "ssh:connect", "recording:read", "db:read", "k8s:impersonate:cluster-admin",
}
var diffRequests = []string{
	"catalog:asset:read", "catalog:folder:create", "access:role:read",
	"identity:group:read", "ssh:login:deploy", "ssh:login:root",
	"ssh:connect", "recording:read", "db:read", "k8s:impersonate:cluster-admin",
	"vault:secret:write",
}

func TestSQLCapMatchMatchesGo(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	const q = `SELECT ($1 = $4 OR $1 = '*') AND ($2 = $5 OR $2 = '*') AND ($3 = $6 OR $3 = '*')`
	for _, p := range diffPatterns {
		ps, pa, pq := NormalizeCap(p)
		for _, r := range diffRequests {
			rs, ra, rq := NormalizeCap(r)
			var got bool
			if err := pool.QueryRow(ctx, q, ps, pa, pq, rs, ra, rq).Scan(&got); err != nil {
				t.Fatalf("query (%q vs %q): %v", p, r, err)
			}
			if want := CapMatch(p, r); got != want {
				t.Errorf("pattern=%q req=%q: SQL=%v Go=%v (cols pat=%q,%q,%q req=%q,%q,%q)",
					p, r, got, want, ps, pa, pq, rs, ra, rq)
			}
		}
	}
}
