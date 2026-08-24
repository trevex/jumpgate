// Package bench holds warden's opt-in API/DB benchmark suite. Every source file
// is guarded by the `bench` build tag, so `go test ./...` and CI never touch it;
// this untagged doc file exists solely so the package always has one buildable
// Go file (matching the e2e package convention), keeping type-checkers and the
// pre-commit linter from erroring with "build constraints exclude all Go files".
// See harness_test.go for the shared ephemeral-Postgres counting pool.
package bench
