package tunnel

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
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gatewayHandler decides how the stub gateway replies to a CONNECT request.
type gatewayHandler func(t *testing.T, target, auth string, conn net.Conn)

// startStubGateway spins up a TLS listener whose leaf carries only a URI SAN
// (no DNS/IP), writes the CA to a temp file, and returns the endpoint + caFile.
func startStubGateway(t *testing.T, handle gatewayHandler) (endpoint, caFile string) {
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
		// URI SAN only: no DNS names or IPs, so hostname verification must fail.
		URIs: []*url.URL{{Scheme: "spiffe", Host: "jumpgate", Path: "/gateway"}},
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
		var target, auth string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "CONNECT ") {
				target = strings.Fields(line)[1]
			}
			if strings.HasPrefix(strings.ToLower(line), "authorization:") {
				auth = strings.TrimSpace(line[len("authorization:"):])
			}
			if line == "\r\n" {
				break
			}
		}
		handle(t, target, auth, conn)
	}()

	return ln.Addr().String(), caFile
}

func TestDialEstablishesTunnelAndEchoes(t *testing.T) {
	const wantTarget = "asset-123"
	const wantToken = "sess-token"

	endpoint, caFile := startStubGateway(t, func(t *testing.T, target, auth string, conn net.Conn) {
		if target != wantTarget {
			t.Errorf("CONNECT target = %q, want %q", target, wantTarget)
		}
		if auth != "Bearer "+wantToken {
			t.Errorf("auth = %q, want Bearer %q", auth, wantToken)
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		// Echo one round.
		buf := make([]byte, 4)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, endpoint, caFile, wantTarget, wantToken)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", buf)
	}
}

func TestDialErrorsOnNon200(t *testing.T) {
	endpoint, caFile := startStubGateway(t, func(_ *testing.T, _, _ string, conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, endpoint, caFile, "asset-x", "tok")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %v, want it to mention 403", err)
	}
}

func TestDialErrorsOnUntrustedCA(t *testing.T) {
	endpoint, _ := startStubGateway(t, func(_ *testing.T, _, _ string, conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})

	// A CA file that does not contain the gateway's cert.
	otherCA := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherCA, []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := Dial(ctx, endpoint, otherCA, "asset-x", "tok"); err == nil {
		t.Fatal("expected error with an untrusted CA, got nil")
	}
}
