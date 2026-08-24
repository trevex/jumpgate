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
