//go:build bench

package bench

import (
	"context"
	"testing"
)

func TestCountingPoolCountsRoundTrips(t *testing.T) {
	pool, counter := sharedDB(t)
	counter.reset()
	var one int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got := counter.load(); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestJitOffByDefault(t *testing.T) {
	pool, _ := sharedDB(t)
	var jit string
	if err := pool.QueryRow(context.Background(), "SHOW jit").Scan(&jit); err != nil {
		t.Fatalf("show jit: %v", err)
	}
	if jitEnabled() {
		return // BENCH_JIT=on: nothing to assert here
	}
	if jit != "off" {
		t.Fatalf("jit = %q, want off (production parity)", jit)
	}
}
