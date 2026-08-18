package authz

import "strings"

// CapMatch reports whether a concrete requested capability is granted by a
// stored capability pattern. Segments are ':'-delimited. In the pattern, '*'
// matches exactly one segment and a trailing '**' matches one-or-more remaining
// segments (and may appear only as the final segment). `requested` is assumed
// concrete (no wildcards); `pattern` may be concrete or a glob.
//
// The proto layer validates stored patterns against the capability grammar, so
// '**' is guaranteed to appear only as the final segment. This function is the
// single auditable home of the glob semantics used by Check.
func CapMatch(pattern, requested string) bool {
	ps := strings.Split(pattern, ":")
	rs := strings.Split(requested, ":")
	for i, p := range ps {
		if p == "**" { // grammar guarantees this is the last segment; matches ≥1 remaining
			return len(rs) > i
		}
		if i >= len(rs) {
			return false // pattern longer than requested
		}
		if p == "*" {
			continue // matches exactly one existing segment (rs[i] exists)
		}
		if p != rs[i] {
			return false
		}
	}
	return len(ps) == len(rs) // no '**': exact segment-count match
}
