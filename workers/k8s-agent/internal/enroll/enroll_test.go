package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	enrollmentv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1/enrollmentv1connect"

	"github.com/trevex/jumpgate/workers/k8s-agent/internal/enroll"
	"github.com/trevex/jumpgate/workers/k8s-agent/internal/mesh"
)

// fakeSigner is a stand-in for warden's EnrollmentService: it parses the CSR,
// signs its public key into a mesh leaf (SPIFFE URI SAN), and returns the leaf
// PEM plus the CA bundle PEM.
type fakeSigner struct {
	enrollmentv1connect.UnimplementedEnrollmentServiceHandler
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func (f *fakeSigner) SignAgentCert(_ context.Context, req *connect.Request[enrollmentv1.SignAgentCertRequest]) (*connect.Response[enrollmentv1.SignAgentCertResponse], error) {
	block, _ := pem.Decode(req.Msg.GetCsrPem())
	if block == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// warden derives the SPIFFE id from the token's bound asset; here it's fixed.
	u, _ := url.Parse("spiffe://jumpgate/agent/pg-primary-db-prod")
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: u.String()},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})
	return connect.NewResponse(&enrollmentv1.SignAgentCertResponse{CertPem: certPEM, CaBundlePem: caPEM}), nil
}

func TestRunWritesMeshLoadableCert(t *testing.T) {
	caCert, caKey := makeCA(t)

	mux := http.NewServeMux()
	mux.Handle(enrollmentv1connect.NewEnrollmentServiceHandler(&fakeSigner{caCert: caCert, caKey: caKey}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "mesh-cert.pem")
	keyFile := filepath.Join(dir, "mesh-key.pem")
	caFile := filepath.Join(dir, "mesh-ca.pem")

	if err := enroll.Run(context.Background(), enroll.Params{
		WardenURL: srv.URL,
		Token:     "t",
		CertFile:  certFile,
		KeyFile:   keyFile,
		CAFile:    caFile,
	}); err != nil {
		t.Fatalf("enroll.Run: %v", err)
	}

	for _, f := range []string{certFile, keyFile, caFile} {
		b, err := os.ReadFile(f) //nolint:gosec // f is a test temp path
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s is empty", f)
		}
		if block, _ := pem.Decode(b); block == nil {
			t.Fatalf("%s is not PEM", f)
		}
	}

	// The written cert+key+CA must be loadable by the agent's own mesh loader —
	// proves the generated key matches the returned (CSR-signed) leaf.
	if _, _, err := mesh.LoadKeyPair(certFile, keyFile, caFile); err != nil {
		t.Fatalf("mesh.LoadKeyPair on enrolled cert: %v", err)
	}
}

// makeCA returns a self-signed ECDSA P-256 mesh CA.
func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-mesh-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
