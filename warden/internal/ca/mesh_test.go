package ca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func parseCertPEM(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMeshCARoundTrip(t *testing.T) {
	caKeyDER, caCertPEM, err := GenerateMeshCA()
	if err != nil {
		t.Fatal(err)
	}
	mca, err := LoadMeshCA(caKeyDER, caCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	const id = "spiffe://jumpgate/worker/w-123"
	_, csrDER, err := GenerateCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, bundlePEM, err := mca.SignCSR(csrDER, id, time.Hour)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	leaf := parseCertPEM(t, leafPEM)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != id {
		t.Fatalf("leaf URI SAN = %v, want %s", leaf.URIs, id)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundlePEM) {
		t.Fatal("append ca bundle")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to mesh CA: %v", err)
	}
}

func TestSignCSRRejectsMismatchedURI(t *testing.T) {
	caKeyDER, caCertPEM, _ := GenerateMeshCA()
	mca, _ := LoadMeshCA(caKeyDER, caCertPEM)
	_, csrDER, _ := GenerateCSR("spiffe://jumpgate/worker/a")
	// Signing must set the SAN from the trusted expectURI, and reject if the CSR's
	// own SAN disagrees with expectURI.
	if _, _, err := mca.SignCSR(csrDER, "spiffe://jumpgate/worker/b", time.Hour); err == nil {
		t.Fatal("expected rejection when CSR SAN != expectURI")
	}
}
