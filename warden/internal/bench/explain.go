//go:build bench

package bench

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// summaryRow is one (operation, profile) result for the optional summary table.
type summaryRow struct {
	Op           string
	Profile      string
	NsPerOp      float64
	QueriesPerOp float64
}

var (
	summaryMu   sync.Mutex
	summaryRows []summaryRow
)

// recordSummary is called by runAcross after each sub-benchmark. It stores a row
// when BENCH_SUMMARY=1; otherwise it is a cheap no-op.
func recordSummary(op, profile string, nsPerOp, queriesPerOp float64) {
	if !summaryEnabled() {
		return
	}
	summaryMu.Lock()
	summaryRows = append(summaryRows, summaryRow{Op: op, Profile: profile, NsPerOp: nsPerOp, QueriesPerOp: queriesPerOp})
	summaryMu.Unlock()
}

// renderSummary formats rows as a markdown table sorted by ns/op descending
// (worst offender first). The benchmark framework re-invokes each sub-benchmark
// body several times while converging on N, so recordSummary sees a given
// (operation, profile) more than once; renderSummary keeps only the last row per
// key (the converged, measured run) before sorting.
func renderSummary(rows []summaryRow) string {
	type key struct{ op, profile string }
	latest := make(map[key]summaryRow, len(rows))
	order := make([]key, 0, len(rows))
	for _, r := range rows {
		k := key{r.Op, r.Profile}
		if _, seen := latest[k]; !seen {
			order = append(order, k)
		}
		latest[k] = r
	}
	deduped := make([]summaryRow, 0, len(order))
	for _, k := range order {
		deduped = append(deduped, latest[k])
	}
	sort.SliceStable(deduped, func(i, j int) bool { return deduped[i].NsPerOp > deduped[j].NsPerOp })
	var b strings.Builder
	b.WriteString("| operation | profile | ns/op | queries/op |\n")
	b.WriteString("|---|---|---:|---:|\n")
	for _, r := range deduped {
		fmt.Fprintf(&b, "| %s | %s | %.0f | %.1f |\n", r.Op, r.Profile, r.NsPerOp, r.QueriesPerOp)
	}
	return b.String()
}

// writeSummary flushes the collected rows to bench-summary.md (called from TestMain
// teardown). No-op unless BENCH_SUMMARY=1 and rows exist.
func writeSummary() {
	if !summaryEnabled() {
		return
	}
	summaryMu.Lock()
	defer summaryMu.Unlock()
	if len(summaryRows) == 0 {
		return
	}
	_ = os.WriteFile("bench-summary.md", []byte(renderSummary(summaryRows)), 0o644)
}

// captureExplain runs EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) for sql on the shared
// pool and appends the plan to bench-explain/<name>.<profile>.txt. It is an on-demand
// diagnostic: call it from a benchmark you are chasing with the specific SQL of the
// hot query. Best-effort — a nil/failed EXPLAIN never breaks the benchmark. No-op
// unless BENCH_EXPLAIN=1.
func captureExplain(tb testing.TB, name, profile, sql string, args ...any) {
	if !explainEnabled() {
		return
	}
	tb.Helper()
	pool, _ := sharedDB(tb)
	rows, err := pool.Query(context.Background(), "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+sql, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	var plan strings.Builder
	fmt.Fprintf(&plan, "-- %s / %s\n", name, profile)
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return
		}
		plan.WriteString(line + "\n")
	}
	_ = os.MkdirAll("bench-explain", 0o755)
	_ = os.WriteFile(filepath.Join("bench-explain", name+"."+profile+".txt"), []byte(plan.String()), 0o644)
}
