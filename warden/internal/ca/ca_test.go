package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHCASignAndVerify(t *testing.T) {
	seed, line, err := GenerateSSHCA()
	if err != nil {
		t.Fatalf("GenerateSSHCA: %v", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(line): %v", err)
	}

	sshCA, err := LoadSSHCA(seed)
	if err != nil {
		t.Fatalf("LoadSSHCA: %v", err)
	}

	// PublicLine must match the generated line.
	if sshCA.PublicLine() != line {
		t.Fatalf("PublicLine mismatch:\n got %q\nwant %q", sshCA.PublicLine(), line)
	}

	// Generate a user key to be certified.
	userEdPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen user key: %v", err)
	}
	userPub, err := ssh.NewPublicKey(userEdPub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	validBefore := time.Now().Add(time.Hour)
	cert, err := sshCA.SignUserKey(userPub, SSHCertParams{
		KeyID:       "k1",
		Principals:  []string{"root"},
		ValidBefore: validBefore,
	})
	if err != nil {
		t.Fatalf("SignUserKey: %v", err)
	}

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("ValidPrincipals = %v, want [root]", cert.ValidPrincipals)
	}
	if cert.KeyId != "k1" {
		t.Fatalf("KeyId = %q, want k1", cert.KeyId)
	}
	if delta := int64(cert.ValidBefore) - validBefore.Unix(); delta < -2 || delta > 2 { //nolint:gosec // Unix seconds fit in int64
		t.Fatalf("ValidBefore off by %d seconds", delta)
	}

	// MarshalCert should round-trip parse as a certificate.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(MarshalCert(cert))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert): %v", err)
	}
	if _, ok := parsed.(*ssh.Certificate); !ok {
		t.Fatalf("marshaled cert did not parse as *ssh.Certificate")
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return bytes.Equal(k.Marshal(), caPub.Marshal())
		},
	}
	if err := checker.CheckCert("root", cert); err != nil {
		t.Fatalf("CheckCert(root): %v", err)
	}
	if err := checker.CheckCert("nobody", cert); err == nil {
		t.Fatal("CheckCert(nobody) succeeded, want failure")
	}
}

func TestX509CASignAndVerify(t *testing.T) {
	keyDER, certPEM, err := GenerateX509CA()
	if err != nil {
		t.Fatalf("GenerateX509CA: %v", err)
	}

	x509CA, err := LoadX509CA(keyDER, certPEM)
	if err != nil {
		t.Fatalf("LoadX509CA: %v", err)
	}
	if x509CA.CertPEM() != certPEM {
		t.Fatal("CertPEM mismatch")
	}

	notAfter := time.Now().Add(time.Hour)
	leafPEM, keyPEM, err := x509CA.SignClient("alice", notAfter)
	if err != nil {
		t.Fatalf("SignClient: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("empty client key PEM")
	}

	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("leaf PEM decode failed")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}

	if leaf.Subject.CommonName != "alice" {
		t.Fatalf("CN = %q, want alice", leaf.Subject.CommonName)
	}
	if delta := leaf.NotAfter.Unix() - notAfter.Unix(); delta < -2 || delta > 2 {
		t.Fatalf("NotAfter off by %d seconds", delta)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certPEM)) {
		t.Fatal("failed to add CA cert to pool")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf.Verify: %v", err)
	}
	// SECURITY: a client leaf must NOT be a CA (would let it sign further certs).
	if leaf.IsCA {
		t.Fatal("client leaf must not be a CA")
	}
}

func TestSSHCARejectsEmptyPrincipals(t *testing.T) {
	seed, _, err := GenerateSSHCA()
	if err != nil {
		t.Fatal(err)
	}
	sshCA, err := LoadSSHCA(seed)
	if err != nil {
		t.Fatal(err)
	}
	_, uPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, _ := ssh.NewPublicKey(uPriv.Public())
	vb := time.Now().Add(time.Hour)
	// An empty ValidPrincipals list is "valid for any principal" in OpenSSH — must be refused.
	if _, err := sshCA.SignUserKey(userPub, SSHCertParams{KeyID: "k", Principals: nil, ValidBefore: vb}); err == nil {
		t.Fatal("nil principals must be refused")
	}
	if _, err := sshCA.SignUserKey(userPub, SSHCertParams{KeyID: "k", Principals: []string{}, ValidBefore: vb}); err == nil {
		t.Fatal("empty principals must be refused")
	}
	if _, err := sshCA.SignUserKey(userPub, SSHCertParams{KeyID: "k", Principals: []string{"root", ""}, ValidBefore: vb}); err == nil {
		t.Fatal("empty-string principal must be refused")
	}
	// A zero/past ValidBefore would mint an effectively non-expiring cert — refuse.
	if _, err := sshCA.SignUserKey(userPub, SSHCertParams{KeyID: "k", Principals: []string{"root"}, ValidBefore: time.Time{}}); err == nil {
		t.Fatal("zero ValidBefore must be refused")
	}
	if _, err := sshCA.SignUserKey(userPub, SSHCertParams{KeyID: "k", Principals: []string{"root"}, ValidBefore: time.Now().Add(-time.Minute)}); err == nil {
		t.Fatal("past ValidBefore must be refused")
	}
}
