// Package mesh is the pg-proxy worker's mTLS + SPIFFE identity plumbing. The
// identity parsing is ported from warden/internal/mesh (not importable across
// modules).
// ponytail: identity format duplicated from warden/internal/mesh/identity.go and
// mesh/src/tls.rs (Rust); unify into a shared module if a fourth consumer appears.
package mesh

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TrustDomain is the SPIFFE trust domain for all jumpgate mesh identities.
const TrustDomain = "jumpgate"

// Identity is a mesh peer's SPIFFE role + id (e.g. role "worker", id "pg-proxy-0").
type Identity struct {
	Role string
	ID   string
}

// SpiffeID renders the identity as spiffe://jumpgate/<role>/<id>.
func (i Identity) SpiffeID() string {
	return fmt.Sprintf("spiffe://%s/%s/%s", TrustDomain, i.Role, i.ID)
}

// ParseIdentity extracts a mesh Identity from a SPIFFE URI SAN. It requires
// scheme spiffe, host == TrustDomain, and exactly two non-empty path segments.
// Ported verbatim from warden/internal/mesh (the source of truth for the format).
func ParseIdentity(u *url.URL) (Identity, error) {
	if u == nil || u.Scheme != "spiffe" {
		return Identity{}, errors.New("mesh: not a spiffe URI")
	}
	if u.Host != TrustDomain {
		return Identity{}, fmt.Errorf("mesh: wrong trust domain %q", u.Host)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Identity{}, fmt.Errorf("mesh: bad spiffe path %q", u.Path)
	}
	return Identity{Role: parts[0], ID: parts[1]}, nil
}
