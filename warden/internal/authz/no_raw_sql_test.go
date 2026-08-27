package authz_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// closureBanned matches hand-written closure SQL: a `WITH RECURSIVE` or a
// hand-rolled user_groups / held_standing / global_held CTE. The single source of
// the shared authorization closures is the DB functions (authz_held,
// authz_held_standing, authz_global_held, authz_user_groups, …); no consumer may
// re-introduce them in Go. The regex matches the bare relation names but NOT the
// `authz_`-prefixed function names (`\bglobal_held\b` does not match inside
// `authz_global_held`), so prose referencing the DB functions is fine.
var closureBanned = regexp.MustCompile(`(?i)WITH RECURSIVE|\bheld_standing\b|\bglobal_held\b|\buser_groups\b`)

// rawLiteralBanned matches a raw `.Query(`/`.QueryRow(`/`.Exec(` whose SQL argument
// is a string literal (backtick or double-quoted) beginning with a data-manipulation
// keyword. This enforces the single database boundary: every query expressible as
// SQL lives in sqlc (internal/postgres), and the only non-sqlc-able op (LISTEN +
// WaitForNotification) goes through the typed postgres.Listen helper — whose
// `"LISTEN "+…` literal is not one of the banned keywords, so it does not trip.
var rawLiteralBanned = regexp.MustCompile("(?is)\\.(Query|QueryRow|Exec)\\(\\s*[a-zA-Z_]\\w*\\s*,\\s*(?:`|\")\\s*(?:--[^\\n]*\\n\\s*)*(SELECT|INSERT|UPDATE|DELETE|WITH)\\b")

// rawSQLExemptDirs are the path prefixes where raw SQL is legitimate: the sqlc
// output + the LISTEN helper (the DB boundary itself), and the build-tagged
// benchmark data-seeding scaffolding (never built by `go test ./...`).
var rawSQLExemptDirs = []string{
	filepath.FromSlash("internal/postgres/"),
	filepath.FromSlash("internal/bench/"),
}

// TestNoRawSQLInGo fails if closure SQL is hand-written in Go anywhere in the module
// (outside generated sqlc), or if any domain package outside internal/postgres
// hand-writes a raw SQL literal. The postgres package (sqlc + the LISTEN helper) is
// the single database boundary.
func TestNoRawSQLInGo(t *testing.T) {
	root := findModuleRoot(t) // walks up to the dir containing go.mod
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil // non-Go or test files (tests may reference names)
		}
		if strings.Contains(p, filepath.FromSlash("/postgres/sqlc/")) {
			return nil // generated
		}
		rel, _ := filepath.Rel(root, p)
		b, _ := os.ReadFile(p) //nolint:gosec // walking the module's own source tree in a test
		if closureBanned.Match(b) {
			t.Errorf("raw closure SQL found in %s (use the authz_* DB functions)", rel)
		}
		if !isRawSQLExempt(rel) && rawLiteralBanned.Match(b) {
			t.Errorf("raw SQL literal found in %s (use sqlc in internal/postgres, or the postgres.Listen helper)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// isRawSQLExempt reports whether rel (a module-relative path) is under one of the
// dirs where raw SQL is legitimate.
func isRawSQLExempt(rel string) bool {
	for _, d := range rawSQLExemptDirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	return false
}

// findModuleRoot walks up from the current working directory until it finds the
// directory containing go.mod (the warden module root).
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from working directory")
		}
		dir = parent
	}
}
