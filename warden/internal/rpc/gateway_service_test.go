package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	gatewayv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1/gatewayv1connect"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/rpc"
)

// meshTestCA is a test mesh CA with helpers to mint identity keypairs.
type meshTestCA struct {
	ca       *ca.MeshCA
	bundle   []byte
	certPool *x509.CertPool
}

func newMeshTestCA(t *testing.T) *meshTestCA {
	t.Helper()
	caKeyDER, caCertPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatalf("generate mesh CA: %v", err)
	}
	mca, err := ca.LoadMeshCA(caKeyDER, caCertPEM)
	if err != nil {
		t.Fatalf("load mesh CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatalf("append CA cert to pool")
	}
	return &meshTestCA{ca: mca, bundle: caCertPEM, certPool: pool}
}

// mint issues a leaf keypair for the given spiffe identity and returns the PEM
// certificate/key plus a tls.Certificate ready for a TLS config.
func (m *meshTestCA) mint(t *testing.T, spiffe string) (certPEM, keyPEM []byte, tlsCert tls.Certificate) {
	t.Helper()
	keyDER, csrDER, err := ca.GenerateCSR(spiffe)
	if err != nil {
		t.Fatalf("generate CSR: %v", err)
	}
	leafPEM, _, err := m.ca.SignCSR(csrDER, spiffe, time.Hour)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return leafPEM, keyPEM, cert
}

// newGatewayTestServer stands up an in-process mTLS httptest server mounting ONLY
// GatewayService behind mesh.Middleware, using a fresh test mesh CA. It returns
// the CA (for minting client certs), the server URL, and the registry so tests
// can register workers.
func newGatewayTestServer(t *testing.T, pubKey ed25519.PublicKey) (*meshTestCA, string, *dataplane.Registry) {
	t.Helper()
	m := newMeshTestCA(t)

	serverCertPEM, serverKeyPEM, _ := m.mint(t, "spiffe://jumpgate/warden/w")
	serverTLS, err := mesh.ServerTLSConfig(serverCertPEM, serverKeyPEM, m.bundle)
	if err != nil {
		t.Fatalf("server TLS config: %v", err)
	}
	// Advertise h2 via ALPN so the server-streaming RPC negotiates HTTP/2.
	serverTLS.NextProtos = []string{"h2", "http/1.1"}

	registry := dataplane.NewRegistry()
	mux := http.NewServeMux()
	path, handler := gatewayv1connect.NewGatewayServiceHandler(rpc.NewGatewayServer(registry, pubKey))
	mux.Handle(path, handler)

	srv := httptest.NewUnstartedServer(mesh.Middleware(mux))
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return m, srv.URL, registry
}

// gatewayClient builds an mTLS connect client identified by the given spiffe.
func gatewayClient(t *testing.T, m *meshTestCA, url, spiffe string) gatewayv1connect.GatewayServiceClient {
	t.Helper()
	_, _, clientCert := m.mint(t, spiffe)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      m.certPool,
			NextProtos:   []string{"h2"},
			// The mesh server leaf carries only a spiffe URI SAN (no DNS/IP SAN),
			// so standard hostname verification against 127.0.0.1 fails. The mesh
			// trust model verifies peers by URI SAN, not hostname; for the test we
			// disable default hostname verification and validate the chain against
			// the mesh CA ourselves via VerifyConnection (which also covers resumed
			// sessions). Server-side mTLS (the property under test) is unaffected.
			InsecureSkipVerify: true, //nolint:gosec // custom chain verification below; hostname check intentionally bypassed for URI-SAN mesh certs
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no server certificate")
				}
				opts := x509.VerifyOptions{Roots: m.certPool, Intermediates: x509.NewCertPool()}
				for _, inter := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(inter)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		},
		ForceAttemptHTTP2: true,
	}
	return gatewayv1connect.NewGatewayServiceClient(&http.Client{Transport: transport}, url)
}

func TestWatchWorkersSnapshotAndDelta(t *testing.T) {
	m, url, registry := newGatewayTestServer(t, testPubKey())

	// Pre-register a worker so the stream opens with a snapshot ADDED for w1.
	registry.SetWorkerMeta("w1", dataplane.WorkerMeta{Protocol: "ssh", Address: "10.0.0.1:22", Capacity: 5})

	client := gatewayClient(t, m, url, "spiffe://jumpgate/gateway/g1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.WatchWorkers(ctx, connect.NewRequest(&gatewayv1.WatchWorkersRequest{}))
	if err != nil {
		t.Fatalf("watch workers: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	// Snapshot: ADDED for w1.
	if !stream.Receive() {
		t.Fatalf("expected snapshot event, receive returned false: %v", stream.Err())
	}
	ev := stream.Msg()
	if ev.GetKind() != gatewayv1.RosterEvent_ADDED || ev.GetWorker().GetWorkerId() != "w1" {
		t.Fatalf("unexpected snapshot event: %+v", ev)
	}
	if ev.GetWorker().GetDataplaneAddress() != "10.0.0.1:22" || ev.GetWorker().GetCapacity() != 5 {
		t.Fatalf("snapshot worker metadata wrong: %+v", ev.GetWorker())
	}

	// Live delta: register w2, expect an ADDED for w2 on the stream.
	registry.SetWorkerMeta("w2", dataplane.WorkerMeta{Protocol: "ssh", Address: "10.0.0.2:22", Capacity: 3})
	if !stream.Receive() {
		t.Fatalf("expected delta event, receive returned false: %v", stream.Err())
	}
	ev = stream.Msg()
	if ev.GetKind() != gatewayv1.RosterEvent_ADDED || ev.GetWorker().GetWorkerId() != "w2" {
		t.Fatalf("unexpected delta event: %+v", ev)
	}
}

func TestWatchWorkersRequiresGateway(t *testing.T) {
	m, url, _ := newGatewayTestServer(t, testPubKey())

	client := gatewayClient(t, m, url, "spiffe://jumpgate/worker/w1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.WatchWorkers(ctx, connect.NewRequest(&gatewayv1.WatchWorkersRequest{}))
	if err != nil {
		assertPermissionDenied(t, err)
		return
	}
	// The permission error may surface on the first Receive for server streams.
	if stream.Receive() {
		t.Fatalf("worker identity unexpectedly received a roster event: %+v", stream.Msg())
	}
	assertPermissionDenied(t, stream.Err())
}

func TestGetSessionVerificationKey(t *testing.T) {
	pub := testPubKey()
	m, url, _ := newGatewayTestServer(t, pub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// gateway identity: returns the injected key.
	gw := gatewayClient(t, m, url, "spiffe://jumpgate/gateway/g1")
	resp, err := gw.GetSessionVerificationKey(ctx, connect.NewRequest(&gatewayv1.GetSessionVerificationKeyRequest{}))
	if err != nil {
		t.Fatalf("get verification key: %v", err)
	}
	if got := resp.Msg.GetEd25519PublicKey(); len(got) != ed25519.PublicKeySize || string(got) != string(pub) {
		t.Fatalf("verification key mismatch: got %d bytes", len(got))
	}

	// worker identity: PermissionDenied.
	wk := gatewayClient(t, m, url, "spiffe://jumpgate/worker/w1")
	_, err = wk.GetSessionVerificationKey(ctx, connect.NewRequest(&gatewayv1.GetSessionVerificationKeyRequest{}))
	assertPermissionDenied(t, err)
}

func testPubKey() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return pub
}

func assertPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PermissionDenied, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v: %v", connect.CodeOf(err), err)
	}
}
