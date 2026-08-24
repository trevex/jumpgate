//go:build bench

package bench

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// queryCounter is a pgx.QueryTracer counting SQL round-trips: every Query,
// QueryRow, and Exec fires TraceQueryStart exactly once.
type queryCounter struct{ n int64 }

func (c *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	atomic.AddInt64(&c.n, 1)
	return ctx
}
func (c *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (c *queryCounter) load() int64                                                     { return atomic.LoadInt64(&c.n) }
func (c *queryCounter) reset()                                                          { atomic.StoreInt64(&c.n, 0) }

// pkgPool/pkgCounter are the process-wide shared counting pool and its counter,
// set up by TestMain (harness_test.go) and consumed by both test and non-test
// files in this package (which is why they live here, not in the _test.go file).
var (
	pkgPool    *pgxpool.Pool
	pkgCounter *queryCounter
)

func jitEnabled() bool      { return os.Getenv("BENCH_JIT") == "on" }
func explainEnabled() bool  { return os.Getenv("BENCH_EXPLAIN") == "1" }
func summaryEnabled() bool  { return os.Getenv("BENCH_SUMMARY") == "1" }
func profileFilter() string { return os.Getenv("BENCH_PROFILE") }

// sharedDB returns the package-wide counting pool and counter.
func sharedDB(tb testing.TB) (*pgxpool.Pool, *queryCounter) {
	tb.Helper()
	if pkgPool == nil {
		tb.Skip("shared pool unavailable (postgres tooling missing)")
	}
	return pkgPool, pkgCounter
}
