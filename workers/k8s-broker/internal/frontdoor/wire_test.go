package frontdoor_test

// TestFrontDoorOverMeshTLS is the whole-stack proof: a test mesh CA signs
// broker/agent/gateway leaf certs; the real broker accepts the agent's reverse
// tunnel; the real front door handler sits behind a mesh-mTLS listener pinning
// role "gateway"; a fake gateway client dials in and round-trips a request all
// the way to a fake API server. No warden, no cluster — fully hermetic.
//
// Cert-plumbing helpers (makeCA/makeLeaf/writePEM) are copied verbatim from
// internal/broker/broker_test.go (unexported, can't be imported cross-package).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/workers/k8s-agent/proxy"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/broker"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/frontdoor"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

func TestFrontDoorOverMeshTLS(t *testing.T) {
	assetID := uuid.New()
	sub := uuid.New()

	// --- Fake API server: captures what the agent forwarded. ---
	var gotUser, gotGroup, gotAuth string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Impersonate-User")
		gotGroup = r.Header.Get("Impersonate-Group")
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "pong")
	}))
	defer api.Close()

	dir := t.TempDir()

	// --- Test mesh CA + broker/agent/gateway leaf certs (SPIFFE URI SANs). ---
	caCert, caKey := makeCA(t)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caCert.Raw)
	brokerCert, brokerKey := makeLeaf(t, "spiffe://jumpgate/broker/broker-0", caCert, caKey)
	agentCert, agentKey := makeLeaf(t, "spiffe://jumpgate/agent/"+assetID.String(), caCert, caKey)
	gwCert, gwKey := makeLeaf(t, "spiffe://jumpgate/gateway/gw-0", caCert, caKey)

	brokerLeaf, brokerPool, err := mesh.LoadKeyPair(brokerCert, brokerKey, caFile)
	if err != nil {
		t.Fatal(err)
	}

	// --- Broker: mesh-mTLS listener pinning role "agent", real broker.Serve. ---
	agentLn := tls.NewListener(mustListen(t), mesh.ServerTLSConfigRole(brokerLeaf, brokerPool, "agent"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := broker.New()
	go func() { _ = b.Serve(ctx, agentLn) }()

	// --- Agent side: dial the broker pinning role "broker", serve the real
	// k8s-agent proxy handler over HTTP/2 (role reversal). ---
	tokenFile := writeFile(t, dir, "sa-token", "sa-token-xyz")
	apiCAFile := writePEM(t, dir, "api-ca.pem", "CERTIFICATE", api.Certificate().Raw)
	agentHandler, err := proxy.New(api.URL, apiCAFile, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	agentLeaf, agentPool, err := mesh.LoadKeyPair(agentCert, agentKey, caFile)
	if err != nil {
		t.Fatal(err)
	}
	agentConn, err := tls.Dial("tcp", agentLn.Addr().String(), mesh.ClientTLSConfigRole(agentLeaf, agentPool, "broker"))
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	defer func() { _ = agentConn.Close() }()
	go (&http2.Server{}).ServeConn(agentConn, &http2.ServeConnOpts{Handler: agentHandler})

	// --- Front door: mesh-mTLS listener pinning role "gateway", plain HTTP/1.1
	// (the gateway blind-pipes kubectl's HTTP/1.1 stream, not h2). ---
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fdTLS := mesh.ServerTLSConfigRole(brokerLeaf, brokerPool, "gateway")
	fdTLS.NextProtos = []string{"http/1.1"}
	fdLn := tls.NewListener(mustListen(t), fdTLS)
	// Wire the per-connection recorder end-to-end: ConnContext supplies the handle
	// the fail-closed tap needs, ConnState finishes + reports on close.
	rec := frontdoor.NewRecorder(nopUploader{}, "broker-0", make(chan frontdoor.SessionEnd, 8))
	fdSrv := &http.Server{
		Handler:           frontdoor.Handler(b, sessiontoken.NewVerifier(pub), rec),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       rec.ConnContext,
		ConnState:         rec.ConnState,
	}
	defer func() { _ = fdSrv.Close() }()
	go func() { _ = fdSrv.Serve(fdLn) }()

	// --- Fake gateway client: dials the front door pinning role "broker". ---
	gwLeaf, gwPool, err := mesh.LoadKeyPair(gwCert, gwKey, caFile)
	if err != nil {
		t.Fatal(err)
	}
	gwTLS := mesh.ClientTLSConfigRole(gwLeaf, gwPool, "broker")
	gwTLS.NextProtos = []string{"http/1.1"}
	httpClient := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return tls.Dial("tcp", fdLn.Addr().String(), gwTLS)
		},
	}}

	tok := mint(t, priv, "kubernetes", sub, assetID, "alice@example.com", []string{"developers"})

	// Retry: the agent's reverse tunnel registers asynchronously after dial.
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, rerr := http.NewRequest(http.MethodGet, "https://front/api/v1/namespaces/default/pods", nil)
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Impersonate-User", "root") // forged; must be stripped
		r, derr := httpClient.Do(req)
		if derr == nil && r.StatusCode == http.StatusOK {
			resp = r
			break
		}
		if r != nil {
			_ = r.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("front door never succeeded: err=%v", derr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Fatalf("body = %q, want %q", body, "pong")
	}
	if gotUser != "alice@example.com" {
		t.Fatalf("Impersonate-User = %q, want %q (forged root must be stripped, email from token)", gotUser, "alice@example.com")
	}
	if gotGroup != "developers" {
		t.Fatalf("Impersonate-Group = %q, want %q", gotGroup, "developers")
	}
	if gotAuth != "Bearer sa-token-xyz" {
		t.Fatalf("Authorization = %q, want SA bearer (agent's, not client's)", gotAuth)
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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
