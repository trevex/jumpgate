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
