package authz_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawClosureSQLInGo fails if closure SQL is hand-written in Go anywhere in
// the warden module (outside generated sqlc). The single source of the shared
// authorization closures is the DB functions (authz_held, authz_held_standing,
// authz_global_held, authz_user_groups, authz_role_goals, …); no consumer may
// re-introduce a `WITH RECURSIVE` closure or a hand-rolled user_groups /
// held_standing / global_held CTE in Go.
//
// The regex intentionally matches the bare relation names (`held_standing`,
// `global_held`, `user_groups`) but NOT the `authz_`-prefixed function names
// (a `_` is a word character, so `\bglobal_held\b` does not match inside
// `authz_global_held`), so prose that references the DB functions is fine.
func TestNoRawClosureSQLInGo(t *testing.T) {
	banned := regexp.MustCompile(`(?i)WITH RECURSIVE|\bheld_standing\b|\bglobal_held\b|\buser_groups\b`)
	// allowlist: the unrelated upward supergroups cycle-check.
	allow := map[string]bool{
		filepath.FromSlash("internal/identity/groups.go"): true,
	}
	root := findModuleRoot(t) // walks up to the dir containing go.mod
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		if strings.HasSuffix(p, "_test.go") {
			return nil // tests may reference names
		}
		if strings.Contains(p, filepath.FromSlash("/postgres/sqlc/")) {
			return nil // generated
		}
		rel, _ := filepath.Rel(root, p)
		if allow[rel] {
			return nil
		}
		b, _ := os.ReadFile(p) //nolint:gosec // walking the module's own source tree in a test
		if banned.Match(b) {
			t.Errorf("raw closure SQL found in %s (use the authz_* DB functions)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
