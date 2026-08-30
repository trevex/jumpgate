package broker_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/workers/k8s-agent/proxy"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/broker"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
)

// TestReverseTunnelRoundTrip is the whole-tunnel proof: a test mesh CA signs a
// broker cert + an agent cert; the real k8s-agent proxy handler is served over
// the HTTP/2 reverse tunnel; a request round-trips broker -> agent -> fake API
// server, and the fake API server sees the SA bearer + Impersonate-* headers.
//
// Certs are minted inline (not via warden/internal/ca, which is import-blocked
// across modules) so the test is hermetic — no warden, no cluster.
func TestReverseTunnelRoundTrip(t *testing.T) {
	const assetID = "pg-primary-db-prod"

	// --- Fake API server: echoes back what the agent forwarded. ---
	var gotAuth, gotUser, gotGroup, gotPath string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser = r.Header.Get("Impersonate-User")
		gotGroup = r.Header.Get("Impersonate-Group")
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "pong")
	}))
	defer api.Close()

	dir := t.TempDir()

	// --- Test mesh CA + broker/agent leaf certs (SPIFFE URI SANs). ---
	caCert, caKey := makeCA(t)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caCert.Raw)
	brokerCert, brokerKey := makeLeaf(t, "spiffe://jumpgate/broker/broker-0", caCert, caKey)
	agentCert, agentKey := makeLeaf(t, "spiffe://jumpgate/agent/"+assetID, caCert, caKey)

	// SA token + API-server CA the agent proxy needs.
	tokenFile := filepath.Join(dir, "sa-token")
	if err := os.WriteFile(tokenFile, []byte("sa-token-xyz"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiCAFile := writePEM(t, dir, "api-ca.pem", "CERTIFICATE", api.Certificate().Raw)

	// --- Broker: mesh-mTLS listener pinning role "agent". ---
	brokerLeaf, brokerPool, err := mesh.LoadKeyPair(brokerCert, brokerKey, caFile)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawLn, mesh.ServerTLSConfigRole(brokerLeaf, brokerPool, "agent"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := broker.New()
	go func() { _ = b.Serve(ctx, tlsLn) }()

	// --- Agent side (in-process): dial the broker pinning role "broker", then
	// serve HTTP/2 (role reversal) with the real proxy handler. ---
	handler, err := proxy.New(api.URL, apiCAFile, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	agentLeaf, agentPool, err := mesh.LoadKeyPair(agentCert, agentKey, caFile)
	if err != nil {
		t.Fatal(err)
	}
	agentTLS := mesh.ClientTLSConfigRole(agentLeaf, agentPool, "broker")
	conn, err := tls.Dial("tcp", tlsLn.Addr().String(), agentTLS)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	go (&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: handler})

	// --- Wait for the tunnel to register, then round-trip a request. ---
	req, err := http.NewRequest(http.MethodGet, "https://tunnel/api/v1/namespaces/default/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Impersonate-User", "alice")
	req.Header.Set("Impersonate-Group", "developers")

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = b.RoundTrip(assetID, req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("RoundTrip never succeeded: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "pong" {
		t.Fatalf("round-trip resp = %d %q", resp.StatusCode, string(body))
	}
	// The tunnel actually carried the request to the fake API server as the SA,
	// with impersonation intact.
	if gotAuth != "Bearer sa-token-xyz" {
		t.Fatalf("API server Authorization = %q, want SA bearer", gotAuth)
	}
	if gotUser != "alice" || gotGroup != "developers" {
		t.Fatalf("Impersonate-* not preserved: user=%q group=%q", gotUser, gotGroup)
	}
	if gotPath != "/api/v1/namespaces/default/pods" {
		t.Fatalf("API server path = %q", gotPath)
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

// makeLeaf signs a mesh leaf for uriSAN and returns PEM cert+key file paths.
func makeLeaf(t *testing.T, uriSAN string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	u, err := url.Parse(uriSAN)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: uriSAN},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = writePEM(t, dir, "cert.pem", "CERTIFICATE", der)
	keyFile = writePEM(t, dir, "key.pem", "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
