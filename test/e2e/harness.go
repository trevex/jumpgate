// Package e2e is a black-box end-to-end suite for the jumpgate test environment.
// It drives the real `jumpgate` CLI (per-actor --context) and `kubectl` against a
// live kind cluster and asserts on their output.
//
// It lives in its own module (not in go.work), so `make ci` — which tests the
// warden and cli modules per-directory — never runs it. Run it explicitly with
// `GOWORK=off go test ./...` and JUMPGATE_E2E=1 against a live cluster (see
// main_test.go); `make kind-e2e` does exactly that.
package e2e

import "regexp"

var idRe = regexp.MustCompile(`"id":\s*"([^"]+)"`)

// jsonID returns the first top-level "id" value in protojson output, or "".
func jsonID(s string) string {
	m := idRe.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
