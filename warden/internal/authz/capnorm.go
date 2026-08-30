package authz

import "strings"

// NormalizeCap decomposes a capability pattern into (scope, action, qualifier)
// columns. `**` fills its position and all trailing columns with `*`; a single
// `*` stays `*` with trailing columns `”`; concrete segments map directly with
// trailing columns `”`. Only the first three segments are represented (the whole
// real vocabulary is ≤3 segments).
func NormalizeCap(pattern string) (scope, action, qualifier string) {
	segs := strings.SplitN(pattern, ":", 3)
	col := [3]string{"", "", ""}
	star := false
	for i := 0; i < 3; i++ {
		if star {
			col[i] = "*"
			continue
		}
		if i >= len(segs) {
			col[i] = ""
			continue
		}
		if segs[i] == "**" {
			col[i] = "*"
			star = true
			continue
		}
		col[i] = segs[i]
	}
	return col[0], col[1], col[2]
}

// ReconstructCap rebuilds the canonical display string from columns: a maximal
// trailing run of `*` reaching the end collapses to `**`; trailing `”` is dropped.
func ReconstructCap(scope, action, qualifier string) string {
	cols := []string{scope, action, qualifier}
	n := len(cols)
	for n > 0 && cols[n-1] == "" {
		n--
	}
	cols = cols[:n]
	run := 0
	for i := len(cols) - 1; i >= 0 && cols[i] == "*"; i-- {
		run++
	}
	if run >= 2 {
		cols = append(cols[:len(cols)-run], "**")
	}
	return strings.Join(cols, ":")
}
