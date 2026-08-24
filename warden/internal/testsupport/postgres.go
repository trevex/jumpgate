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

// StartPostgresProcess boots an ephemeral PostgreSQL cluster in a temp dir using
// the initdb/pg_ctl/createdb binaries on PATH (provided by the Nix devshell). It
// listens on a Unix socket, creates a database named "jumpgate", and returns a DSN
// plus a stop func that tears the cluster down and removes its temp dirs. It is
// testing-independent so callers without a *testing.T (e.g. a benchmark TestMain)
// can manage the lifecycle themselves. An error is returned if the tooling is
// missing or the cluster fails to start.
func StartPostgresProcess() (dsn string, stop func(), err error) {
	for _, bin := range []string{"initdb", "pg_ctl", "createdb"} {
		if _, err := exec.LookPath(bin); err != nil {
			return "", nil, fmt.Errorf("postgres tooling not on PATH (%s); run inside `nix develop`: %w", bin, err)
		}
	}

	dir, err := os.MkdirTemp("", "pgdata")
	if err != nil {
		return "", nil, fmt.Errorf("mkdir data: %w", err)
	}
	dataDir := filepath.Join(dir, "data")
	// Postgres appends "/.s.PGSQL.5432" to the -k socket directory, and the full
	// socket path must fit in sockaddr_un.sun_path (~107 bytes). Under the Nix
	// devshell a "/tmp/nix-shell.XXXXXX" prefix plus a long data-dir path can
	// overflow that limit and make pg_ctl fail to bind ("could not start
	// server"). Put the socket in a short, independent temp dir.
	sockDir, err := os.MkdirTemp("", "pgs")
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("mkdir sock: %w", err)
	}

	cleanup := func() {
		_ = exec.Command("pg_ctl", "-D", dataDir, "-m", "immediate", "-w", "stop").Run() //nolint:gosec,errcheck // best-effort teardown
		_ = os.RemoveAll(sockDir)
		_ = os.RemoveAll(dir)
	}

	run := func(name string, args ...string) error {
		cmd := exec.Command(name, args...) //nolint:gosec // fixed binary names from a trusted PATH (devshell)
		if out, e := cmd.CombinedOutput(); e != nil {
			return fmt.Errorf("%s %v: %w\n%s", name, args, e, out)
		}
		return nil
	}

	if err := run("initdb", "-D", dataDir, "-U", "postgres", "--auth=trust", "-E", "UTF8"); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := run("pg_ctl", "-D", dataDir, "-o", fmt.Sprintf("-k %s -h ''", sockDir),
		"-l", filepath.Join(dir, "pg.log"), "-w", "start"); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := run("createdb", "-h", sockDir, "-U", "postgres", "jumpgate"); err != nil {
		cleanup()
		return "", nil, err
	}

	dsn = fmt.Sprintf("postgres://postgres@/jumpgate?host=%s", sockDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("connect ephemeral pg: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		cleanup()
		return "", nil, fmt.Errorf("ping ephemeral pg: %w", err)
	}
	pool.Close()

	return dsn, cleanup, nil
}

// StartPostgres is the testing.TB-scoped convenience wrapper: it starts an
// ephemeral cluster and registers teardown on tb.Cleanup, skipping the test when
// the tooling is unavailable. It accepts testing.TB so both *testing.T and
// *testing.B can use it.
func StartPostgres(tb testing.TB) string {
	tb.Helper()
	dsn, stop, err := StartPostgresProcess()
	if err != nil {
		tb.Skipf("%v", err)
	}
	tb.Cleanup(stop)
	return dsn
}
