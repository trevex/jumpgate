package cmd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/trevex/jumpgate/cli/internal/config"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
)

const testToken = "test-token"

// stubWarden implements the Catalog and Session handlers the connect flow needs.
type stubWarden struct {
	catalogv1connect.UnimplementedCatalogServiceHandler
	sessionv1connect.UnimplementedSessionServiceHandler

	assetID         string
	gatewayEndpoint string
	sessionToken    string

	gotAssetID string
	gotKcPub   []byte
}

func (s *stubWarden) ResolveAsset(_ context.Context, req *connect.Request[catalogv1.ResolveAssetRequest]) (*connect.Response[catalogv1.ResolveAssetResponse], error) {
	if req.Header().Get("Authorization") != "Bearer "+testToken {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("bad token"))
	}
	return connect.NewResponse(&catalogv1.ResolveAssetResponse{AssetId: s.assetID, Path: req.Msg.GetRef()}), nil
}

func (s *stubWarden) CreateSession(_ context.Context, req *connect.Request[sessionv1.CreateSessionRequest]) (*connect.Response[sessionv1.CreateSessionResponse], error) {
	if req.Header().Get("Authorization") != "Bearer "+testToken {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("bad token"))
	}
	s.gotAssetID = req.Msg.GetAssetId()
	s.gotKcPub = req.Msg.GetClientSshPublicKey()
	return connect.NewResponse(&sessionv1.CreateSessionResponse{
		SessionToken:    s.sessionToken,
		GatewayEndpoint: s.gatewayEndpoint,
	}), nil
}

func startStubWarden(t *testing.T, s *stubWarden) string {
	t.Helper()
	mux := http.NewServeMux()
	cpath, chandler := catalogv1connect.NewCatalogServiceHandler(s)
	spath, shandler := sessionv1connect.NewSessionServiceHandler(s)
	mux.Handle(cpath, chandler)
	mux.Handle(spath, shandler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// startEchoGateway mirrors the tunnel stub: a TLS listener with a URI-SAN leaf
// that accepts the CONNECT and echoes.
func startEchoGateway(t *testing.T) (endpoint, caFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gateway"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "jumpgate", Path: "/gateway"}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		buf := make([]byte, 8)
		n, err := br.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	return ln.Addr().String(), caFile
}

func TestRunConnectEstablishesTunnel(t *testing.T) {
	gwEndpoint, caFile := startEchoGateway(t)

	sw := &stubWarden{
		assetID:         "asset-uuid-1",
		gatewayEndpoint: gwEndpoint,
		sessionToken:    "sess-tok",
	}
	wardenURL := startStubWarden(t, sw)

	cctx := config.Context{WardenAddr: wardenURL, Token: testToken, CAFile: caFile}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := runConnect(ctx, cctx, "root", "myhost")
	if err != nil {
		t.Fatalf("runConnect: %v", err)
	}
	defer func() { _ = res.tunnel.Close() }()

	if sw.gotAssetID != "asset-uuid-1" {
		t.Errorf("CreateSession asset id = %q, want asset-uuid-1", sw.gotAssetID)
	}
	if len(sw.gotKcPub) == 0 || !strings.HasPrefix(string(sw.gotKcPub), "ssh-ed25519 ") {
		t.Errorf("client public key = %q, want an ssh-ed25519 authorized key", sw.gotKcPub)
	}
	if res.signer == nil {
		t.Error("expected a client signer")
	}

	// The tunnel is live: it echoes.
	if _, err := res.tunnel.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := res.tunnel.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hi" {
		t.Errorf("echo = %q, want hi", buf)
	}
}

func TestRunConnectRequiresToken(t *testing.T) {
	cctx := config.Context{WardenAddr: "http://localhost:1", Token: ""}
	_, err := runConnect(context.Background(), cctx, "root", "myhost")
	if err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("want a login-required error, got %v", err)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name         string
		target, flag string
		wantLogin    string
		wantAsset    string
		wantErr      bool
	}{
		{name: "login@asset", target: "root@myhost", wantLogin: "root", wantAsset: "myhost"},
		{name: "bare asset with flag", target: "myhost", flag: "admin", wantLogin: "admin", wantAsset: "myhost"},
		{name: "flag overrides", target: "root@myhost", flag: "admin", wantLogin: "admin", wantAsset: "myhost"},
		{name: "empty asset", target: "root@", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			login, asset, err := parseTarget(tc.target, tc.flag)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if login != tc.wantLogin || asset != tc.wantAsset {
				t.Errorf("got (%q,%q), want (%q,%q)", login, asset, tc.wantLogin, tc.wantAsset)
			}
		})
	}
}
