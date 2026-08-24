//go:build bench

package bench

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// TestMain boots one ephemeral PostgreSQL for the whole package, migrates it, and
// builds the shared counting pool with production-parity connection config
// (pgx-google-uuid registration + jit off unless BENCH_JIT=on). go test runs
// TestMain for benchmark-only runs too, so this covers `-bench` invocations. It
// must live in a _test.go file — Go only treats TestMain as the test entry point
// there — but the reusable pool/counter/predicates it wires live in harness.go so
// non-test files (profile.go, generate.go, explain.go) can reference them.
func TestMain(m *testing.M) {
	dsn, stop, err := testsupport.StartPostgresProcess()
	if err != nil {
		// No devshell PG tooling: skip the whole suite cleanly.
		fmt.Fprintf(os.Stderr, "bench: skipping — %v\n", err)
		os.Exit(0)
	}
	defer stop()

	if err := migrate.Up(dsn); err != nil {
		fmt.Fprintf(os.Stderr, "bench: migrate: %v\n", err)
		stop()
		os.Exit(1)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: parse config: %v\n", err)
		stop()
		os.Exit(1)
	}
	pkgCounter = &queryCounter{}
	cfg.ConnConfig.Tracer = pkgCounter
	jitSetting := "off"
	if jitEnabled() {
		jitSetting = "on"
	}
	// Set jit via a startup RuntimeParam rather than a SET in AfterConnect: the
	// parameter rides the connection-startup packet, so it costs no SQL round-trip
	// and never pollutes the query counter on a freshly-opened pooled connection.
	cfg.ConnConfig.RuntimeParams["jit"] = jitSetting
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pkgPool, err = pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: pool: %v\n", err)
		stop()
		os.Exit(1)
	}

	code := m.Run()
	pkgPool.Close()
	stop()
	os.Exit(code)
}
