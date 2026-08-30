package authz

import "testing"

func TestNormalizeCap(t *testing.T) {
	cases := []struct{ in, s, a, q string }{
		{"**", "*", "*", "*"},
		{"catalog:**", "catalog", "*", "*"},
		{"ssh:login:**", "ssh", "login", "*"},
		{"catalog:asset:*", "catalog", "asset", "*"},
		{"ssh:*", "ssh", "*", ""},
		{"recording:read", "recording", "read", ""},
		{"catalog:asset:read", "catalog", "asset", "read"},
		{"ssh:connect", "ssh", "connect", ""},
		{"k8s:group:system:masters", "k8s", "group", "system:masters"},
		{"k8s:group:developers", "k8s", "group", "developers"},
	}
	for _, c := range cases {
		s, a, q := NormalizeCap(c.in)
		if s != c.s || a != c.a || q != c.q {
			t.Errorf("NormalizeCap(%q)=(%q,%q,%q), want (%q,%q,%q)", c.in, s, a, q, c.s, c.a, c.q)
		}
	}
}

func TestReconstructCanonical(t *testing.T) {
	cases := []struct{ s, a, q, out string }{
		{"*", "*", "*", "**"},
		{"catalog", "*", "*", "catalog:**"},
		{"ssh", "login", "*", "ssh:login:*"},
		{"ssh", "*", "", "ssh:*"},
		{"recording", "read", "", "recording:read"},
		{"catalog", "asset", "read", "catalog:asset:read"},
	}
	for _, c := range cases {
		if got := ReconstructCap(c.s, c.a, c.q); got != c.out {
			t.Errorf("ReconstructCap(%q,%q,%q)=%q, want %q", c.s, c.a, c.q, got, c.out)
		}
	}
}

// TestReconstructMatchPreserving verifies that Normalize→Reconstruct is a
// semantics-preserving round-trip: CapMatch(original, req) must equal
// CapMatch(reconstructed, req) for every (pattern, request) pair in the
// cross-product used by the SQL CapMatch differential test.
func TestReconstructMatchPreserving(t *testing.T) {
	for _, p := range diffPatterns {
		s, a, q := NormalizeCap(p)
		reconstructed := ReconstructCap(s, a, q)
		for _, r := range diffRequests {
			want := CapMatch(p, r)
			got := CapMatch(reconstructed, r)
			if got != want {
				t.Errorf("round-trip mismatch: pattern=%q reconstructed=%q req=%q: CapMatch(orig)=%v CapMatch(recon)=%v",
					p, reconstructed, r, want, got)
			}
		}
	}
}

func TestNormalizeReconstructRoundTripColonQualifier(t *testing.T) {
	const in = "k8s:group:system:masters"
	s, a, q := NormalizeCap(in)
	if got := ReconstructCap(s, a, q); got != in {
		t.Fatalf("round-trip = %q, want %q", got, in)
	}
}
