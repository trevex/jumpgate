package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// newCA builds an in-memory ECDSA CA and returns the CA cert + key + a pool
// trusting it.
func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return caCert, key, pool
}

// issueLeaf issues a leaf cert with the given SPIFFE URI SAN signed by parent.
// If parent is nil the leaf is self-signed (chains to nothing trusted).
func issueLeaf(t *testing.T, spiffe string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spiffe},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustURL(t, spiffe)},
	}
	signer, signerKey := caCert, caKey
	if signer == nil {
		signer, signerKey = tmpl, key // self-signed
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

const (
	wardenSpiffe  = "spiffe://jumpgate/warden/warden"
	gatewaySpiffe = "spiffe://jumpgate/gateway/gw"
)

func TestClientTLSConfigPinsServerSpiffe(t *testing.T) {
	caCert, caKey, pool := newCA(t)
	warden := issueLeaf(t, wardenSpiffe, caCert, caKey)
	gateway := issueLeaf(t, gatewaySpiffe, caCert, caKey)
	rogue := issueLeaf(t, wardenSpiffe, nil, nil) // right SPIFFE, wrong chain

	self := issueLeaf(t, "spiffe://jumpgate/worker/self", caCert, caKey)
	cfg := ClientTLSConfig(self, pool, wardenSpiffe)

	if err := cfg.VerifyConnection(connState(warden)); err != nil {
		t.Errorf("warden leaf should verify: %v", err)
	}
	if err := cfg.VerifyConnection(connState(gateway)); err == nil {
		t.Error("gateway leaf should be rejected (SPIFFE mismatch)")
	}
	if err := cfg.VerifyConnection(connState(rogue)); err == nil {
		t.Error("non-chaining leaf should be rejected (chain failure)")
	}
}

func TestServerTLSConfigPinsClientSpiffe(t *testing.T) {
	caCert, caKey, pool := newCA(t)
	warden := issueLeaf(t, wardenSpiffe, caCert, caKey)
	gateway := issueLeaf(t, gatewaySpiffe, caCert, caKey)
	rogue := issueLeaf(t, gatewaySpiffe, nil, nil)

	self := issueLeaf(t, "spiffe://jumpgate/worker/self", caCert, caKey)
	cfg := ServerTLSConfig(self, pool, gatewaySpiffe)

	if err := cfg.VerifyPeerCertificate([][]byte{gateway.Leaf.Raw}, nil); err != nil {
		t.Errorf("gateway leaf should verify: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{warden.Leaf.Raw}, nil); err == nil {
		t.Error("warden leaf should be rejected (SPIFFE mismatch)")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{rogue.Leaf.Raw}, nil); err == nil {
		t.Error("non-chaining leaf should be rejected (chain failure)")
	}
}

// connState wraps a single leaf; the CA lives in the config's pool so a lone
// leaf verifies.
func connState(c tls.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}}
}
