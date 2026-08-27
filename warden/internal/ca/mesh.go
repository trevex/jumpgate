package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"time"
)

// -----------------------------------------------------------------------------
// Mesh CA (ECDSA P-256)
// -----------------------------------------------------------------------------
//
// The mesh CA is a dedicated internal CA (separate from the SSH/X.509 vault
// CAs) that issues mTLS identities for the warden/gateway/worker mesh. Leaf
// certificates carry the component identity in a URI SAN of the form
// spiffe://jumpgate/<role>/<id>. Component private keys never leave the
// component: each component generates a CSR (GenerateCSR) and warden signs it
// (SignCSR), stamping the trusted identity into the leaf's URI SAN.

// MeshCA is a self-signed mesh certificate authority (ECDSA P-256).
type MeshCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
}

// GenerateMeshCA returns a new self-signed mesh CA: the PKCS#8 DER of the P-256
// key (to be sealed by the caller) and the CA certificate PEM (public material
// for mesh mTLS trust).
func GenerateMeshCA() (caKeyDER []byte, caCertPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating P-256 mesh CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "jumpgate-mesh-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating mesh CA certificate: %w", err)
	}
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caKeyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling mesh CA key: %w", err)
	}
	return caKeyDER, caCertPEM, nil
}

// LoadMeshCA reconstructs a mesh CA from its PKCS#8 key DER and certificate PEM.
func LoadMeshCA(caKeyDER, caCertPEM []byte) (*MeshCA, error) {
	keyAny, err := x509.ParsePKCS8PrivateKey(caKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parsing mesh CA key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mesh CA key is %T, want *ecdsa.PrivateKey", keyAny)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("decoding mesh CA certificate PEM: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing mesh CA certificate: %w", err)
	}
	return &MeshCA{key: key, cert: cert, certPEM: caCertPEM}, nil
}

// GenerateCSR is a component-side helper: it generates a fresh P-256 key and a
// CSR carrying the given URI SAN. The returned private key DER (PKCS#8) stays
// with the component; only the CSR DER is sent to warden for signing.
func GenerateCSR(uriSAN string) (keyDER []byte, csrDER []byte, err error) {
	u, err := url.Parse(uriSAN)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing URI SAN %q: %w", uriSAN, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating P-256 key: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		URIs: []*url.URL{u},
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling key: %w", err)
	}
	return keyDER, csrDER, nil
}

// SignCSR verifies the CSR's self-signature and issues a mesh leaf certificate
// whose URI SAN is set from the trusted expectURI (never from the CSR). If the
// CSR carries URI SANs, they must equal exactly [expectURI] or the request is
// rejected. The leaf is valid for ttl and usable for both client and server
// mTLS. It returns the leaf PEM and the CA certificate PEM as the bundle.
func (c *MeshCA) SignCSR(csrDER []byte, expectURI string, ttl time.Duration) (leafPEM []byte, caBundlePEM []byte, err error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("verifying CSR signature: %w", err)
	}
	expect, err := url.Parse(expectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing expected URI %q: %w", expectURI, err)
	}
	// SECURITY: do not trust the CSR's SANs. If the CSR asserts any URI SANs,
	// they must match the trusted expectURI exactly; otherwise reject.
	if len(csr.URIs) > 0 {
		if len(csr.URIs) != 1 || csr.URIs[0].String() != expectURI {
			return nil, nil, fmt.Errorf("CSR URI SAN %v does not match expected %q", csr.URIs, expectURI)
		}
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: expectURI},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{expect},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating mesh leaf certificate: %w", err)
	}
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return leafPEM, c.certPEM, nil
}
