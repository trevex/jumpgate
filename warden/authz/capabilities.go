package authz

import "strings"

// CapMatch reports whether a concrete requested capability is granted by a
// stored capability pattern. Segments are ':'-delimited. In the pattern, '*'
// matches exactly one segment and a trailing '**' matches one-or-more remaining
// segments (and may appear only as the final segment). `requested` is assumed
// concrete (no wildcards); `pattern` may be concrete or a glob.
//
// The proto layer validates stored patterns against the capability grammar, so
// '**' is normally only ever the final segment. CapMatch does NOT rely on that:
// it enforces "'**' only as the final segment" defensively and fails CLOSED on a
// malformed pattern, so a pattern reaching this function via a non-proto path
// (direct sqlc, future writers) can never match more than its literal segments
// intend. This function is the single auditable home of the glob semantics used
// by Check.
func CapMatch(pattern, requested string) bool {
	ps := strings.Split(pattern, ":")
	rs := strings.Split(requested, ":")
	for i, p := range ps {
		if p == "**" {
			// '**' is only meaningful as the final segment. A non-final '**' is a
			// malformed pattern; fail closed rather than silently dropping the
			// segments after it (which would match far too broadly).
			if i != len(ps)-1 {
				return false
			}
			return len(rs) > i // matches ≥1 remaining segment
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
