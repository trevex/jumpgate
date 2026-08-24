//go:build bench

package bench

import (
	"strings"
	"testing"
)

func TestSummaryTableSortsByNsDescending(t *testing.T) {
	rows := []summaryRow{
		{Op: "A", Profile: "wide", NsPerOp: 100, QueriesPerOp: 2},
		{Op: "B", Profile: "deep", NsPerOp: 900, QueriesPerOp: 7},
	}
	out := renderSummary(rows)
	if strings.Index(out, "| B ") > strings.Index(out, "| A ") {
		t.Fatalf("summary not sorted by ns/op desc:\n%s", out)
	}
}

// TestSummaryTableDedupesKeepingLast locks the behavior that the benchmark
// framework's repeated sub-benchmark invocations collapse to one row per
// (operation, profile), keeping the last (converged) measurement.
func TestSummaryTableDedupesKeepingLast(t *testing.T) {
	rows := []summaryRow{
		{Op: "A", Profile: "wide", NsPerOp: 500, QueriesPerOp: 2},
		{Op: "A", Profile: "wide", NsPerOp: 120, QueriesPerOp: 2},
	}
	out := renderSummary(rows)
	if strings.Count(out, "| A | wide ") != 1 {
		t.Fatalf("expected exactly one A/wide row, got:\n%s", out)
	}
	if !strings.Contains(out, "| A | wide | 120 |") {
		t.Fatalf("expected the last (120) measurement to win, got:\n%s", out)
	}
	if strings.Contains(out, "| 500 |") {
		t.Fatalf("stale first measurement (500) should have been dropped:\n%s", out)
	}
}
