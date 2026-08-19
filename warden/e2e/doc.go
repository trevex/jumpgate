// Package e2e contains the opt-in, full-stack SSH connect integration test. The
// test itself is guarded by the `e2e` build tag (see ssh_connect_test.go) and is
// excluded from the default build and from `make ci`; run it with `make e2e-ssh`.
//
// This file carries no build tag so the package is never empty under the default
// build (which would otherwise trip tooling that type-checks every package).
package e2e
