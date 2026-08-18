// Package ca implements jumpgate's certificate authorities: an SSH user CA
// (Ed25519) and an X.509 client CA (ECDSA P-256). CA private material is
// returned in a sealed-ready form (raw seed / PKCS#8 DER) for the caller to
// encrypt via the secrets sealer; public material (authorized_keys line / cert
// PEM) is distributed to hosts for trust.
package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

// -----------------------------------------------------------------------------
// SSH CA (Ed25519)
// -----------------------------------------------------------------------------

// SSHCA is an SSH certificate authority backed by an Ed25519 key pair.
type SSHCA struct {
	signer ssh.Signer
}

// GenerateSSHCA returns a new ed25519 CA: the 32-byte private seed (to be sealed
// by the caller) and the authorized_keys CA line (public material for hosts).
func GenerateSSHCA() (seed []byte, publicLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generating ed25519 CA key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("wrapping CA public key: %w", err)
	}
	seed = priv.Seed()
	publicLine = string(ssh.MarshalAuthorizedKey(sshPub))
	return seed, publicLine, nil
}

// LoadSSHCA reconstructs an SSH CA from its 32-byte Ed25519 seed.
func LoadSSHCA(seed []byte) (*SSHCA, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid ed25519 seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("creating SSH signer: %w", err)
	}
	return &SSHCA{signer: signer}, nil
}

// SSHCertParams holds parameters for signing an SSH user certificate.
type SSHCertParams struct {
	KeyID       string
	Principals  []string
	ValidBefore time.Time
}

// SignUserKey signs a user's public key and returns an SSH user certificate.
func (c *SSHCA) SignUserKey(userPub ssh.PublicKey, p SSHCertParams) (*ssh.Certificate, error) {
	// SECURITY: an empty ValidPrincipals list means "valid for ANY principal" in
	// OpenSSH — an all-accounts (incl. root) cert. Refuse to sign one here as
	// defense-in-depth, independent of any caller-side entitlement check.
	if len(p.Principals) == 0 {
		return nil, fmt.Errorf("refusing to sign an SSH cert with no principals (would authorize every account)")
	}
	for _, pr := range p.Principals {
		if pr == "" {
			return nil, fmt.Errorf("refusing to sign an SSH cert with an empty principal")
		}
	}
	now := time.Now()
	// SECURITY: a zero/past ValidBefore casts to a huge uint64 → an effectively
	// non-expiring cert. The credential must be time-bounded (never outlive its
	// grant), so refuse a non-future expiry here rather than trust the caller.
	if p.ValidBefore.IsZero() || !p.ValidBefore.After(now) {
		return nil, fmt.Errorf("refusing to sign an SSH cert with a non-future ValidBefore")
	}
	serial, err := randomSerialUint64()
	if err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             userPub,
		CertType:        ssh.UserCert,
		KeyId:           p.KeyID,
		Serial:          serial,
		ValidPrincipals: p.Principals,
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()), //nolint:gosec // Unix seconds are positive and well within uint64
		ValidBefore:     uint64(p.ValidBefore.Unix()),         //nolint:gosec // Unix seconds are positive and well within uint64
		Permissions: ssh.Permissions{
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("signing SSH certificate: %w", err)
	}
	return cert, nil
}

// PublicLine returns the CA public key in OpenSSH authorized_keys format.
func (c *SSHCA) PublicLine() string {
	return string(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))
}

// MarshalCert returns the certificate in OpenSSH authorized_keys format.
func MarshalCert(cert *ssh.Certificate) []byte {
	return ssh.MarshalAuthorizedKey(cert)
}

func randomSerialUint64() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generating serial: %w", err)
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// -----------------------------------------------------------------------------
// X.509 CA (ECDSA P-256)
// -----------------------------------------------------------------------------

// X509CA is a self-signed X.509 client certificate authority (ECDSA P-256).
type X509CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM string
}

// GenerateX509CA returns a self-signed CA: PKCS#8 DER of the P-256 key (to be
// sealed) and the CA certificate PEM (public material for mTLS trust).
func GenerateX509CA() (keyDER []byte, certPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generating P-256 CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "jumpgate x509 CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", fmt.Errorf("creating CA certificate: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling CA key: %w", err)
	}
	return keyDER, certPEM, nil
}

// LoadX509CA reconstructs an X.509 CA from its PKCS#8 key DER and certificate PEM.
func LoadX509CA(keyDER []byte, certPEM string) (*X509CA, error) {
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is %T, want *ecdsa.PrivateKey", keyAny)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("decoding CA certificate PEM: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return &X509CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// SignClient issues a new client leaf certificate (with a freshly generated
// P-256 key) for the given common name, valid until notAfter. It returns the
// leaf certificate PEM and the client private key PEM (PKCS#8).
func (c *X509CA) SignClient(cn string, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating client key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &clientKey.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating client certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling client key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// CertPEM returns the CA certificate in PEM form.
func (c *X509CA) CertPEM() string {
	return c.certPEM
}

func randomSerial() (*big.Int, error) {
	// 128-bit random serial.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return serial, nil
}
