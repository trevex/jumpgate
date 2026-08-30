package authz

import "strings"

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

// Connect-predicate capability prefixes per asset kind: the qualifier that
// follows names the target account/role.
const (
	SSHLoginPrefix = "ssh:login:"
	DBLoginPrefix  = "db:login:"
	K8sGroupPrefix = "k8s:group:"
)

// EntitledLoginsFor returns the order-preserving subset of allowedLogins for
// which the "prefix+<login>" capability is held (e.g. "ssh:login:root" or
// "db:login:app"). Returns nil (not an empty slice) when none match.
func (c Capabilities) EntitledLoginsFor(prefix string, allowedLogins []string) []string {
	var out []string
	for _, login := range allowedLogins {
		if c.Allows(prefix + login) {
			out = append(out, login)
		}
	}
	return out
}

// EntitledLogins is the SSH-kind convenience wrapper (prefix "ssh:login:").
func (c Capabilities) EntitledLogins(allowedLogins []string) []string {
	return c.EntitledLoginsFor(SSHLoginPrefix, allowedLogins)
}

// ConcreteQualifiers returns the deduped, order-preserving set of concrete
// qualifiers held under prefix — i.e. every held pattern "prefix+<qual>" whose
// <qual> contains no wildcard. Unlike EntitledLoginsFor (which tests a known
// allow-list), this ENUMERATES what the closure carries: k8s groups are an
// attribute projected verbatim downstream, not a predicate. Wildcard-bearing
// patterns name no concrete attribute and are skipped, so holding `**` or
// `k8s:group:*` yields no group (an intended safety property).
func (c Capabilities) ConcreteQualifiers(prefix string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, p := range c {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok || rest == "" || strings.Contains(rest, "*") {
			continue
		}
		if _, dup := seen[rest]; dup {
			continue
		}
		seen[rest] = struct{}{}
		out = append(out, rest)
	}
	return out
}

// FolderReadCap is the subtree-wide catalog READ capability. Held on a folder F it
// confers READ (visibility + per-object open) of everything homed at or under F —
// descendant sub-folders, assets, roles, and groups — so a delegate governing a
// folder need not also be granted each object-type read cap. It is READ-ONLY: it
// confers neither CONNECT (ssh:login) nor any authoring/grant capability, and it is
// deliberately NOT part of Covers / the no-escalation subset rule, so holding it can
// never let a delegate BIND or GRANT an object read cap they do not themselves hold.
const FolderReadCap = "catalog:folder:read"

// ReadAllowed reports whether these caps satisfy a management READ of an object
// whose own read cap is objectReadCap, honoring the subtree-wide FolderReadCap: a
// caller allowed either the object's own read cap OR catalog:folder:read at the
// object's scope may read it. Single-sourced so every per-object read gate broadens
// identically. This is a read-visibility predicate ONLY — it must never be consulted
// by grantable/subset logic (see FolderReadCap).
func (c Capabilities) ReadAllowed(objectReadCap string) bool {
	return c.Allows(objectReadCap) || c.Allows(FolderReadCap)
}
