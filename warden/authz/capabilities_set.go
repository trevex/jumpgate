package authz

// Capabilities is the flattened set of capability patterns a user holds on one
// asset (via the held standing closure). It lets a caller test several concrete
// capabilities against a single closure fetch instead of re-running the recursive
// held query per capability. Allows/EntitledLogins do the glob matching in Go via
// CapMatch, exactly as Check does.
type Capabilities []string

// Allows reports whether any held pattern matches the concrete capability. It uses
// the SAME per-pattern glob semantics as Check (CapMatch): any single matching
// pattern grants. Because CapMatch is a pure per-pattern predicate with no
// cross-pattern state, OR-ing across the flattened patterns here is identical to
// Check's per-row unmarshal-then-match loop.
func (c Capabilities) Allows(capability string) bool {
	for _, p := range c {
		if CapMatch(p, capability) {
			return true
		}
	}
	return false
}

// EntitledLogins returns the order-preserving subset of allowedLogins for which
// the "ssh:login:<login>" capability is held. Returns nil (not an empty slice)
// when none match.
func (c Capabilities) EntitledLogins(allowedLogins []string) []string {
	var out []string
	for _, login := range allowedLogins {
		if c.Allows("ssh:login:" + login) {
			out = append(out, login)
		}
	}
	return out
}
