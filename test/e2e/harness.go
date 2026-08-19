// Package e2e is a black-box end-to-end suite for the jumpgate test environment.
// It drives the real `jumpgate` CLI (per-actor --context) and `kubectl` against a
// live kind cluster and asserts on their output.
//
// It lives in its own module (not in go.work), so `make ci` — which tests the
// warden and cli modules per-directory — never runs it. Run it explicitly with
// `GOWORK=off go test ./...` and JUMPGATE_E2E=1 against a live cluster (see
// main_test.go); `make kind-e2e` does exactly that.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// env holds process-wide handles shared by every actor: the built CLI binary, the
// per-run config dir (one XDG_CONFIG_HOME holding all three contexts), and the
// exported gateway mesh-CA path used by `connect`.
type env struct {
	jgBin     string // path to the built jumpgate binary
	configDir string // XDG_CONFIG_HOME for all actor contexts
	meshCA    string // exported gateway mesh CA PEM
	wardenURL string // http://localhost:8080
	suffix    string // optional name suffix (E2E_SUFFIX) for repeat runs on a persistent cluster
}

// name appends the run suffix to a base object name. With no suffix (the default,
// used by `make kind-e2e` on a fresh cluster) it returns base unchanged.
func (e *env) name(base string) string { return base + e.suffix }

var idRe = regexp.MustCompile(`"id":\s*"([^"]+)"`)

// jsonID returns the first top-level "id" value in protojson output, or "".
func jsonID(s string) string {
	m := idRe.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// run executes name with args, returns combined stdout+stderr, and fails the test
// on non-zero exit (with the output attached for diagnosis).
func run(t *testing.T, extraEnv []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s\nexit: %v\noutput:\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// asActor runs `jumpgate --context <ctx> <args...>` with the shared config dir.
func (e *env) asActor(t *testing.T, ctx string, args ...string) string {
	t.Helper()
	full := append([]string{"--context", ctx}, args...)
	return run(t, []string{"XDG_CONFIG_HOME=" + e.configDir}, e.jgBin, full...)
}

// login stores credentials for actor ctx in the shared config dir. login has its
// own local --context flag (the name to store under), distinct from the global
// --context used by asActor to select a stored context.
func (e *env) login(t *testing.T, ctx, email, pass string) {
	t.Helper()
	run(t, []string{"XDG_CONFIG_HOME=" + e.configDir}, e.jgBin,
		"login", "--context", ctx,
		"--warden-addr", e.wardenURL, "--ca", e.meshCA,
		"--email", email, "--password", pass)
}

// kubectl runs kubectl with the ambient kubeconfig and returns stdout+stderr.
func (e *env) kubectl(t *testing.T, args ...string) string {
	t.Helper()
	return run(t, nil, "kubectl", args...)
}

// exportMeshCA writes the gateway's mesh CA to e.meshCA (needed by `connect`).
func (e *env) exportMeshCA(t *testing.T) {
	t.Helper()
	pem := e.kubectl(t, "get", "secret", "jumpgate-gateway-ext",
		"-o", `go-template={{index .data "ca.crt" | base64decode}}`)
	if strings.TrimSpace(pem) == "" {
		t.Fatal("exported mesh CA is empty")
	}
	if err := os.WriteFile(e.meshCA, []byte(pem), 0o600); err != nil {
		t.Fatalf("write mesh CA: %v", err)
	}
}

// fixturesDir returns <repo>/test/fixtures, creating it. The suite runs with CWD
// = test/e2e, so the repo root is two levels up.
func fixturesDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "fixtures"))
	if err != nil {
		t.Fatalf("abs fixtures: %v", err)
	}
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatalf("mkdir fixtures: %v", err)
	}
	return d
}
