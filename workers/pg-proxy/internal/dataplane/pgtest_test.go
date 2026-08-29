package dataplane

// ponytail: minimal pg launcher duplicated from warden/internal/testsupport;
// unify if a third module needs it.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// startPostgres boots an ephemeral, TLS-enabled PostgreSQL listening on a free
// 127.0.0.1 TCP port, with a scram password login role (app/s3cr3t) and a
// database (appdb). TLS is required because DialTarget uses sslmode=prefer with
// the plaintext fallback stripped (Fallbacks=nil), so the primary attempt is
// TLS-only. It skips the test when initdb is not on PATH. Returns the
// "127.0.0.1:<port>" address, the database name, and a stop func.
func startPostgres(t *testing.T) (addr, db string, stop func()) {
	t.Helper()
	for _, bin := range []string{"initdb", "pg_ctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("initdb not on PATH; run inside `nix develop`: %v", err)
		}
	}

	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	// Short, independent socket dir: the full "<dir>/.s.PGSQL.<port>" path must fit
	// in sockaddr_un.sun_path (~107 bytes), and a long TempDir can overflow it.
	sockDir, err := os.MkdirTemp("", "pgs")
	if err != nil {
		t.Fatalf("mkdir sock: %v", err)
	}

	run := func(name string, args ...string) {
		t.Helper()
		if out, e := exec.Command(name, args...).CombinedOutput(); e != nil { //nolint:gosec // fixed devshell binaries
			t.Fatalf("%s %v: %v\n%s", name, args, e, out)
		}
	}

	run("initdb", "-D", dataDir, "-U", "postgres", "--auth=trust", "-E", "UTF8")

	crt, key := selfSignedCert(t)
	writeFile(t, filepath.Join(dataDir, "server.crt"), crt)
	writeFile(t, filepath.Join(dataDir, "server.key"), key) // 0600: postgres refuses a group/world-readable key

	// scram for the app role over TCP genuinely verifies the injected password;
	// local trust keeps the superuser setup connection simple. Order matters: the
	// app-specific scram line must precede the catch-all trust line.
	writeFile(t, filepath.Join(dataDir, "pg_hba.conf"), []byte(
		"local all all trust\n"+
			"host all app 127.0.0.1/32 scram-sha-256\n"+
			"host all all 127.0.0.1/32 trust\n"+
			"host all all ::1/128 trust\n"))

	port := freePort(t)
	stop = func() {
		_ = exec.Command("pg_ctl", "-D", dataDir, "-m", "immediate", "-w", "stop").Run() //nolint:gosec,errcheck // best-effort teardown
		_ = os.RemoveAll(sockDir)
	}
	opts := fmt.Sprintf("-c listen_addresses=127.0.0.1 -p %d -c unix_socket_directories=%s -c ssl=on -c ssl_cert_file=%s -c ssl_key_file=%s",
		port, sockDir, filepath.Join(dataDir, "server.crt"), filepath.Join(dataDir, "server.key"))
	run("pg_ctl", "-D", dataDir, "-o", opts, "-l", filepath.Join(dir, "pg.log"), "-w", "start")
	ok := false
	defer func() {
		if !ok {
			stop()
		}
	}()

	// Superuser setup over the unix socket (trust): create the login role and db.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres@/postgres?host=%s&port=%d", sockDir, port))
	if err != nil {
		t.Fatalf("connect superuser: %v", err)
	}
	for _, q := range []string{
		"CREATE ROLE app LOGIN PASSWORD 's3cr3t'",
		"CREATE DATABASE appdb OWNER app",
	} {
		if _, err := conn.Exec(ctx, q); err != nil { // no-arg Exec => simple protocol, so CREATE DATABASE is allowed
			_ = conn.Close(ctx)
			t.Fatalf("setup %q: %v", q, err)
		}
	}
	_ = conn.Close(ctx)

	ok = true
	return fmt.Sprintf("127.0.0.1:%d", port), "appdb", stop
}

func freePort(t *testing.T) int {
	t.Helper()
	// ponytail: TOCTOU window between close and pg bind; fine for a single test.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}
