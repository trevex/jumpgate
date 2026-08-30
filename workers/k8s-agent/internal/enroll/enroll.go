// Package enroll bootstraps the k8s-agent's mesh identity: it generates a keypair
// + CSR and calls warden's EnrollmentService.SignAgentCert with a single-use
// token, then writes the returned asset-scoped mesh cert to disk. warden derives
// the SPIFFE id from the token's bound asset — the CSR subject/SANs are ignored.
package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"

	enrollmentv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1/enrollmentv1connect"
)

// Params configures a single enrollment run: where to reach warden, the
// single-use token, an optional PEM CA to trust warden's TLS, and the mesh cert
// file paths the signed identity is written to.
type Params struct {
	WardenURL string
	Token     string
	CAPEM     []byte
	CertFile  string
	KeyFile   string
	CAFile    string
}

// Run generates an ECDSA keypair + CSR, calls SignAgentCert (retrying transient
// failures), and writes the returned leaf cert, generated key, and CA bundle to
// the configured mesh cert file paths. Rejections (NotFound/PermissionDenied/
// InvalidArgument) fail fast.
func Run(ctx context.Context, p Params) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "jumpgate-agent"},
	}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	client := enrollmentv1connect.NewEnrollmentServiceClient(httpClient(p.CAPEM), p.WardenURL)

	var resp *connect.Response[enrollmentv1.SignAgentCertResponse]
	for attempt := 0; ; attempt++ {
		resp, err = client.SignAgentCert(ctx, connect.NewRequest(&enrollmentv1.SignAgentCertRequest{
			EnrollmentToken: p.Token, CsrPem: csrPEM,
		}))
		if err == nil {
			break
		}
		if code := connect.CodeOf(err); code == connect.CodeNotFound || code == connect.CodePermissionDenied || code == connect.CodeInvalidArgument {
			return fmt.Errorf("enrollment rejected: %w", err)
		}
		if attempt >= 30 {
			return fmt.Errorf("enrollment: giving up after retries: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(p.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(p.CertFile, resp.Msg.GetCertPem(), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(p.CAFile, resp.Msg.GetCaBundlePem(), 0o600); err != nil {
		return err
	}
	return nil
}

func httpClient(caPEM []byte) *http.Client {
	if len(caPEM) == 0 {
		return http.DefaultClient
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}
