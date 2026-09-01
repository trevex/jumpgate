package authz

import (
	"strings"

	"github.com/google/uuid"
)

// ScopeKind names the three management scopes at which capabilities are held.
type ScopeKind int

const (
	// ScopeGlobal is the tenant-wide scope: capabilities held via scopeless standing
	// bindings (no folder/asset dimension). Global caps apply everywhere.
	ScopeGlobal ScopeKind = iota
	// ScopeFolder is a folder object scope: caps held on that folder (plus global).
	ScopeFolder
	// ScopeAsset is an asset object scope: caps held on that asset (plus global).
	ScopeAsset
)

// Scope identifies where a management capability check is evaluated. For
// ScopeGlobal the ID is unused (zero). For ScopeFolder/ScopeAsset the ID is the
// object's uuid.
type Scope struct {
	Kind ScopeKind
	ID   uuid.UUID
}

// GlobalScope returns the tenant-wide scope.
func GlobalScope() Scope { return Scope{Kind: ScopeGlobal} }

// FolderScope returns the object scope for a folder.
func FolderScope(id uuid.UUID) Scope { return Scope{Kind: ScopeFolder, ID: id} }

// AssetScope returns the object scope for an asset.
func AssetScope(id uuid.UUID) Scope { return Scope{Kind: ScopeAsset, ID: id} }

// Covers reports whether ANY held capability pattern subsumes the target
// capability pattern. Unlike CapMatch (which matches a glob pattern against a
// CONCRETE requested capability), Covers answers pattern-vs-pattern subsumption:
// does a held pattern authorize AT LEAST everything the target pattern denotes?
// This is used to gate management operations whose required capability is itself
// expressed as a (possibly wildcarded) pattern.
//
// Segments are ':'-delimited. In a held pattern: a trailing '**' subsumes any
// non-empty target tail; a '*' subsumes exactly one existing target segment that
// is itself '*' or concrete but NOT '**' (a single '*' cannot cover the
// one-or-more that '**' denotes); a concrete segment subsumes only the identical
// literal. With no '**' in the held pattern, subsumption requires equal segment
// counts. An empty/nil held set covers nothing.
func Covers(held []string, target string) bool {
	ts := strings.Split(target, ":")
	for _, h := range held {
		if covers1(strings.Split(h, ":"), ts) {
			return true
		}
	}
	return false
}

// covers1 reports whether a single held pattern (segments h) subsumes the target
// pattern (segments t). See Covers for the segment semantics.
func covers1(h, t []string) bool {
	for i, hs := range h {
		if hs == "**" {
			// A non-final '**' is malformed. Fail CLOSED (return false) rather than
			// treat it as final — this matches CapMatch's fail-closed handling and
			// keeps the two sibling glob engines that gate escalation in agreement.
			// (Unreachable via canonical caps: ReconstructCap only ever emits a
			// trailing '**'.)
			if i != len(h)-1 {
				return false
			}
			// Trailing '**' subsumes any non-empty remaining target tail.
			return len(t) > i
		}
		if i >= len(t) {
			return false // held pattern longer than target
		}
		if hs == "*" {
			// '*' covers one existing target segment, but NOT a '**' (which denotes
			// one-or-more) — a single-segment wildcard cannot subsume that.
			if t[i] == "**" {
				return false
			}
			continue
		}
		// concrete held segment subsumes only the identical literal target segment.
		if hs != t[i] {
			return false
		}
	}
	// no '**' consumed the tail: subsumption requires exact segment-count match.
	return len(h) == len(t)
}
