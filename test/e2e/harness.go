// Package e2e is a black-box end-to-end suite for the jumpgate test environment.
// It drives the real `jumpgate` CLI (per-actor --context) and `kubectl` against a
// live kind cluster and asserts on their output.
//
// It is its own module in the go workspace, but `make ci` tests the warden and cli
// modules per-directory and never reaches it. Run it explicitly with JUMPGATE_E2E=1
// against a live cluster (see main_test.go); `make kind-e2e` does exactly that.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

// jsonField returns the first top-level string value for key `field` in protojson
// output, or "". Used to read the asset `path` from `assets ssh create -o json`.
func jsonField(s, field string) string {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(field) + `":\s*"([^"]+)"`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// folderIDByPath parses a `folders list -o json` array (protojson objects with
// camelCase keys) and returns the id of the folder whose path equals want, or "".
// Used to resolve a parent folder id for `folders create --parent`, which takes a
// UUID rather than a DNS path.
func folderIDByPath(t *testing.T, listJSON, want string) string {
	t.Helper()
	var folders []struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(listJSON), &folders); err != nil {
		t.Fatalf("parse folders list: %v\noutput:\n%s", err, listJSON)
	}
	for _, f := range folders {
		if f.Path == want {
			return f.ID
		}
	}
	return ""
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

// asActorFails runs `jumpgate --context <ctx> <args...>` like asActor but asserts a
// NON-ZERO exit (an authorization/validation denial). It returns the combined
// stdout+stderr, and fails the test if the command unexpectedly SUCCEEDS. It mirrors
// asActor's exec path (same binary, same shared config dir) with the error check
// inverted.
func (e *env) asActorFails(t *testing.T, ctx string, args ...string) string {
	t.Helper()
	full := append([]string{"--context", ctx}, args...)
	cmd := exec.Command(e.jgBin, full...)
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+e.configDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected %s to fail, but it succeeded\noutput:\n%s", strings.Join(full, " "), out)
	}
	return string(out)
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

// asActorStdin is asActor but feeds stdinData to the command's stdin (for
// `assets ssh login set --password-stdin`).
func (e *env) asActorStdin(t *testing.T, ctx, stdinData string, args ...string) string {
	t.Helper()
	full := append([]string{"--context", ctx}, args...)
	cmd := exec.Command(e.jgBin, full...)
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+e.configDir)
	cmd.Stdin = strings.NewReader(stdinData)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jumpgate %s\nexit: %v\noutput:\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// kubectl runs kubectl with the ambient kubeconfig and returns stdout+stderr.
func (e *env) kubectl(t *testing.T, args ...string) string {
	t.Helper()
	return run(t, nil, "kubectl", args...)
}

// resetSQL truncates every mutable domain table and re-seeds the bootstrap admin
// (preserving its password hash + the ** role and its global standing binding), so a
// top-level test starts from a clean catalog on the shared cluster. Infra material —
// the mesh/SSH/session CAs (ca_keys, session_signing_keys) and the worker roster
// (worker_presence) — is preserved. The email must match adminEmail (scenario_test.go).
const resetSQL = `DO $$
DECLARE v_hash text; v_uid uuid; v_rid uuid;
BEGIN
  SELECT password_hash INTO v_hash FROM users WHERE email = 'admin@demo.test';
  IF v_hash IS NULL THEN RAISE EXCEPTION 'admin user not found; cannot reset'; END IF;
  TRUNCATE users, auth_tokens, roles, role_capabilities, role_bindings, role_grants,
    groups, group_memberships, folders, assets, catalog_names, ssh_asset_config,
    ssh_asset_login, asset_secrets, request_policies, request_policy_subjects,
    access_requests, access_request_approvals, access_grants, live_sessions,
    session_recordings, audit_log, audit_outbox CASCADE;
  INSERT INTO users (email, display_name, password_hash)
    VALUES ('admin@demo.test','admin@demo.test',v_hash) RETURNING id INTO v_uid;
  INSERT INTO roles (name) VALUES ('admin') RETURNING id INTO v_rid;
  INSERT INTO role_capabilities (role_id, scope, action, qualifier) VALUES (v_rid,'*','*','*');
  INSERT INTO role_bindings (role_id, subject_user_id) VALUES (v_rid, v_uid);
END $$;`

// reset wipes mutable data on the shared cluster and re-seeds the admin, so the
// calling top-level test gets an isolated, clean catalog even though every test runs
// against the same persistent cluster. It runs psql inside the in-cluster postgres
// deployment; each test calls it first, and Go runs tests sequentially, so the last
// test's fixtures are the ones left standing for the browser e2e (TestUISeed).
func (e *env) reset(t *testing.T) {
	t.Helper()
	e.kubectl(t, "exec", "deploy/jumpgate-postgres", "-c", "postgres", "--",
		"psql", "-U", "jumpgate", "-d", "jumpgate", "-v", "ON_ERROR_STOP=1", "-c", resetSQL)
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

// completedSessionID parses a `recordings list -o json` array (protojson objects
// with camelCase keys) and returns the sessionId of the first recording whose own
// status is "completed", or "" if none. Pairing the status with its own record —
// rather than matching "completed" and "first id" independently across the blob —
// keeps the pick correct even if the list holds more than one recording.
func completedSessionID(listJSON string) string {
	var recs []struct {
		SessionID string `json:"sessionId"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal([]byte(listJSON), &recs); err != nil {
		return ""
	}
	for _, r := range recs {
		if r.Status == "completed" {
			return r.SessionID
		}
	}
	return ""
}

// connectWithStdin runs `jumpgate connect` as actor ctx, feeding script on stdin
// under a timeout. `connect` has no command-arg form: with non-TTY stdin it runs
// the piped input as a non-interactive shell over the tunnel.
func (e *env) connectWithStdin(t *testing.T, ctx, target, script string) string {
	t.Helper()
	cmd := exec.Command(e.jgBin, "--context", ctx, "connect", target, "--ca", e.meshCA)
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+e.configDir)
	cmd.Stdin = strings.NewReader(script)
	// After a timeout Kill, bound how long Wait blocks on the output pipes so the
	// reader goroutine reaps instead of leaking if a child holds them open.
	cmd.WaitDelay = 5 * time.Second
	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		ch <- res{out, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("connect failed: %v\noutput:\n%s", r.err, r.out)
		}
		return string(r.out)
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("connect timed out after 30s")
		return ""
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
