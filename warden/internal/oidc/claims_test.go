package oidc

import "testing"

// TestClaimParsing exercises stringClaim/extractGroups directly against
// hostile/malformed claim maps (no DB, no network): the only path these
// helpers normally run on is inside Exchange, well past the network call, so
// this is the one hermetic check on "no panic on hostile claims".
func TestClaimParsing(t *testing.T) {
	t.Run("stringClaim", func(t *testing.T) {
		cases := []struct {
			name string
			raw  map[string]any
			key  string
			want string
		}{
			{"missing key", map[string]any{}, "email", ""},
			{"nil value", map[string]any{"email": nil}, "email", ""},
			{"wrong type number", map[string]any{"email": 42}, "email", ""},
			{"wrong type bool", map[string]any{"email": true}, "email", ""},
			{"wrong type object", map[string]any{"email": map[string]any{"x": 1}}, "email", ""},
			{"correct string", map[string]any{"email": "a@x.com"}, "email", "a@x.com"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := stringClaim(tc.raw, tc.key)
				if got != tc.want {
					t.Fatalf("stringClaim() = %q, want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("extractGroups", func(t *testing.T) {
		cases := []struct {
			name string
			raw  map[string]any
			want []string
		}{
			{"missing key", map[string]any{}, nil},
			{"nil value", map[string]any{"groups": nil}, nil},
			{"wrong type number", map[string]any{"groups": 42}, nil},
			{"wrong type bool", map[string]any{"groups": true}, nil},
			{"wrong type object", map[string]any{"groups": map[string]any{"x": 1}}, nil},
			{"empty array", map[string]any{"groups": []any{}}, []string{}},
			{"mixed array drops non-strings", map[string]any{"groups": []any{"a", 1, nil, true, "b"}}, []string{"a", "b"}},
			{"bare string", map[string]any{"groups": "solo-group"}, []string{"solo-group"}},
			{"empty bare string", map[string]any{"groups": ""}, nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := extractGroups(tc.raw, "groups")
				if len(got) != len(tc.want) {
					t.Fatalf("extractGroups() = %#v, want %#v", got, tc.want)
				}
				for i := range got {
					if got[i] != tc.want[i] {
						t.Fatalf("extractGroups() = %#v, want %#v", got, tc.want)
					}
				}
			})
		}

		// Empty claim key name (unconfigured groups claim) always degrades to nil.
		if got := extractGroups(map[string]any{"groups": []any{"a"}}, ""); got != nil {
			t.Fatalf("extractGroups with empty claim name = %#v, want nil", got)
		}
	})
}
