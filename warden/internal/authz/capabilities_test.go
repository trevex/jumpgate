package authz

import "testing"

func TestCapMatch(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		requested string
		want      bool
	}{
		// Concrete pattern matches only itself.
		{"exact-2seg", "k8s:connect", "k8s:connect", true},
		{"exact-3seg", "k8s:impersonate:cluster-admin", "k8s:impersonate:cluster-admin", true},
		{"exact-mismatch-action", "k8s:connect", "k8s:access", false},
		{"exact-mismatch-scope", "db:connect", "ssh:connect", false},
		{"concrete-not-deeper", "k8s:access", "k8s:access:foo", false},
		{"concrete-not-shallower", "k8s:access:foo", "k8s:access", false},

		// Single '*' matches exactly one segment.
		{"star-connect", "k8s:*", "k8s:connect", true},
		{"star-access", "k8s:*", "k8s:access", true},
		{"star-not-3seg", "k8s:*", "k8s:impersonate:cluster-admin", false},
		{"star-star-3seg", "k8s:*:*", "k8s:impersonate:cluster-admin", true},
		{"star-star-not-2seg", "k8s:*:*", "k8s:connect", false},
		{"impersonate-star", "k8s:impersonate:*", "k8s:impersonate:cluster-admin", true},
		{"impersonate-star-neg", "k8s:impersonate:*", "k8s:connect", false},

		// Leading '*' matches any scope.
		{"star-connect-ssh", "*:connect", "ssh:connect", true},
		{"star-connect-db", "*:connect", "db:connect", true},
		{"star-connect-k8s", "*:connect", "k8s:connect", true},
		{"star-connect-neg-action", "*:connect", "ssh:access", false},
		{"star-connect-neg-depth", "*:connect", "k8s:impersonate:cluster-admin", false},

		// Trailing '**' matches one-or-more remaining segments.
		{"dstar-connect", "k8s:**", "k8s:connect", true},
		{"dstar-impersonate", "k8s:**", "k8s:impersonate:cluster-admin", true},
		{"dstar-deep", "k8s:**", "k8s:a:b:c:d", true},
		// '**' requires at least one remaining segment: 'k8s' alone has no k8s scope,
		// but even a bare 'k8s' (1 seg) must not match 'k8s:**' (needs ≥1 after k8s).
		{"dstar-needs-remaining", "k8s:**", "k8s", false},

		// Pattern longer than requested → false.
		{"pattern-longer", "k8s:a:b", "k8s:a", false},

		// Requested longer than a concrete pattern → false.
		{"requested-longer", "k8s:a", "k8s:a:b", false},

		// Defense-in-depth: a malformed non-final '**' (grammar-rejected at the
		// proto layer, but possible via direct sqlc / future writers) must fail
		// CLOSED — it must not drop the segments after '**' and match broadly.
		{"dstar-nonfinal-malformed", "k8s:**:x", "k8s:connect:x", false},
		{"dstar-nonfinal-malformed-deep", "k8s:**:x", "k8s:a:b:c", false},
		// A wildcard char in the (assumed-concrete) requested arg is treated
		// literally — it cannot widen a grant.
		{"literal-star-requested", "k8s:connect", "k8s:*", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapMatch(tc.pattern, tc.requested); got != tc.want {
				t.Fatalf("CapMatch(%q, %q) = %v, want %v", tc.pattern, tc.requested, got, tc.want)
			}
		})
	}
}
