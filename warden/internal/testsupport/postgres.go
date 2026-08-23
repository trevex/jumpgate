// Package testsupport provides throwaway infrastructure for integration tests.
package testsupport

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartPostgres boots an ephemeral PostgreSQL cluster in a temp dir using the
// initdb/pg_ctl binaries on PATH (provided by the Nix devshell). It listens on a
// Unix socket inside the temp dir, creates a database named "jumpgate", and
// returns a DSN. The cluster is stopped and deleted on test cleanup.
func StartPostgres(t *testing.T) string {
	t.Helper()
	for _, bin := range []string{"initdb", "pg_ctl", "createdb"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("postgres tooling not on PATH (%s); run inside `nix develop`", bin)
		}
	}

	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	// Postgres appends "/.s.PGSQL.5432" to the -k socket directory, and the full
	// socket path must fit in sockaddr_un.sun_path (~107 bytes). t.TempDir() embeds
	// the test name and, under the Nix devshell, a "/tmp/nix-shell.XXXXXX" prefix,
	// which for long test names overflows that limit and makes pg_ctl fail to bind
	// ("could not start server"). Put the socket in a short, independent temp dir.
	sockDir, err := os.MkdirTemp("", "pgs")
	if err != nil {
		t.Fatalf("mkdir sock: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...) //nolint:gosec // fixed binary names from a trusted PATH (devshell)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}

	run("initdb", "-D", dataDir, "-U", "postgres", "--auth=trust", "-E", "UTF8")
	run("pg_ctl", "-D", dataDir, "-o", fmt.Sprintf("-k %s -h ''", sockDir),
		"-l", filepath.Join(dir, "pg.log"), "-w", "start")
	t.Cleanup(func() {
		_ = exec.Command("pg_ctl", "-D", dataDir, "-m", "immediate", "-w", "stop").Run() //nolint:gosec,errcheck // best-effort teardown
	})
	run("createdb", "-h", sockDir, "-U", "postgres", "jumpgate")

	dsn := fmt.Sprintf("postgres://postgres@/jumpgate?host=%s", sockDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect ephemeral pg: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping ephemeral pg: %v", err)
	}
	pool.Close()

	return dsn
}
