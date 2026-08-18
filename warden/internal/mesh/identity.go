// Package mesh provides identity + mTLS helpers for jumpgate's internal service
// mesh. Components authenticate to one another with certificates whose URI SAN
// encodes their identity: spiffe://jumpgate/<role>/<id> (role ∈ worker|gateway|warden).
package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// TrustDomain is the fixed SPIFFE trust domain for the jumpgate mesh.
const TrustDomain = "jumpgate"

// Identity is a mesh peer's identity, parsed from its cert URI SAN.
type Identity struct {
	Role string // worker | gateway | warden
	ID   string
}

// SpiffeID renders the identity as spiffe://jumpgate/<role>/<id>.
func (i Identity) SpiffeID() string {
	return fmt.Sprintf("spiffe://%s/%s/%s", TrustDomain, i.Role, i.ID)
}

// ParseIdentity extracts an Identity from a spiffe:// URI SAN.
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

type ctxKey struct{}

// WithIdentity returns a context carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IdentityFromContext returns the mesh identity attached to ctx, if any.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// ServerTLSConfig builds a server-side mTLS config that REQUIRES and VERIFIES a
// client certificate chaining to the mesh CA bundle.
func ServerTLSConfig(certPEM, keyPEM, caBundlePEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mesh server keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBundlePEM) {
		return nil, errors.New("mesh: bad CA bundle")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// PeerIdentity extracts the verified peer identity from a request's client cert.
func PeerIdentity(r *http.Request) (Identity, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, false
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if id, err := ParseIdentity(u); err == nil {
			return id, true
		}
	}
	return Identity{}, false
}

// Middleware attaches the verified peer identity to the request context; requests
// without a valid mesh identity are rejected (401). Wrap the mesh mux with this.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := PeerIdentity(r)
		if !ok {
			http.Error(w, "mesh identity required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}
