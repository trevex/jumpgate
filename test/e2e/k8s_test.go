package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// enrollTokenRe matches the single-use token `assets k8s create` prints on the
// line after "Enrollment token".
var enrollTokenRe = regexp.MustCompile(`(?s)Enrollment token[^\n]*\n\s*(\S+)`)

// TestKubernetes drives the whole k8s vertical end-to-end on kind: create a k8s
// asset (minting an enrollment token), deploy the agent with that token so it
// enrolls (token -> CSR -> mesh cert), grant a user the `k8s:group:developers`
// capability, then via `jumpgate k8s` + kubectl assert that `get pods` is allowed,
// `get secrets -n kube-system` is Forbidden, and a k8s audit recording lands with
// both outcomes (200 for pods, 403 for the forbidden secrets read).
//
// One test, one reset cycle: the agent's mesh cert is asset-scoped and reset
// recreates the asset each run, so the agent pod is (re)deployed inside the test
// with the fresh token. The broker + agent RBAC are installed by the chart at
// bring-up; only the agent pod + its enrollment Secret are per-test.
func TestKubernetes(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	e := shared
	e.reset(t)
	t.Cleanup(func() { e.teardownAgent() })

	folder := e.name("clusters")
	userEmail := e.name("k8s-alice") + "@demo.test"

	e.exportMeshCA(t)
	e.login(t, "admin", adminEmail, adminPass)
	e.asActor(t, "admin", "folders", "create", folder)

	// Create the asset; capture BOTH the printed enrollment token and the asset
	// id/path from the same `-o json` output (the token is free text, the asset
	// is JSON).
	createOut := e.asActor(t, "admin", "assets", "k8s", "create", e.name("prod"),
		"--folder", folder, "-o", "json")
	assetID := jsonID(createOut)
	assetPath := jsonField(createOut, "path")
	if assetID == "" || assetPath == "" {
		t.Fatalf("no asset id/path in create output:\n%s", createOut)
	}
	m := enrollTokenRe.FindStringSubmatch(createOut)
	if len(m) < 2 {
		t.Fatalf("no enrollment token in create output:\n%s", createOut)
	}
	token := m[1]

	// Deploy the agent with the token so it enrolls on first start.
	e.deployAgent(t, token)

	// Grant a connecting user the developers group (concrete cap; wildcards yield
	// no group). Standing binding on the asset, mirroring the pg test.
	e.asActor(t, "admin", "roles", "create", e.name("k8sdev"),
		"--folder", folder, "--capability", "k8s:group:developers")
	e.asActor(t, "admin", "users", "create", userEmail, "--name", "K8sAlice", "--password", alicePass)
	roleRef := e.name("k8sdev") + "." + folder
	e.asActor(t, "admin", "bindings", "create",
		"--role", roleRef, "--user", userEmail, "--asset", assetPath)
	e.login(t, "k8s-alice", userEmail, alicePass)

	// The `k8s kubeconfig` command itself must produce a sane kubeconfig.
	kcOut := e.asActor(t, "k8s-alice", "k8s", "kubeconfig", assetPath)
	for _, want := range []string{"server: https://", "command: jumpgate", "k8s", "auth"} {
		if !strings.Contains(kcOut, want) {
			t.Fatalf("kubeconfig missing %q:\n%s", want, kcOut)
		}
	}

	// Build a test-runnable kubeconfig: absolute plugin binary (no PATH dependency),
	// --context k8s-alice + XDG_CONFIG_HOME/HOME in the exec env, and the gateway on
	// the host-mapped port with TLS verification skipped (kubectl hostname-verifies
	// `server:`; the gateway's serving cert has no localhost SAN — production uses a
	// real DNS SAN, out of scope for this authz/recording test).
	kubeHome := t.TempDir()
	kc := e.writeK8sKubeconfig(t, assetPath, kubeHome)

	// Wait for the tunnel: the agent must enroll + dial the broker + the broker must
	// advertise the asset before CreateKubernetesSession can route. Poll get-pods.
	var podsOut string
	deadline := time.Now().Add(150 * time.Second)
	var lastErr string
	for time.Now().Before(deadline) {
		out, err := e.kubectlKC(kc, kubeHome, "get", "pods", "-A")
		if err == nil {
			podsOut = out
			break
		}
		lastErr = out
		time.Sleep(3 * time.Second)
	}
	if podsOut == "" {
		e.dumpAgent(t)
		t.Fatalf("kubectl get pods never succeeded within 150s; last error:\n%s", lastErr)
	}

	// Forbidden: the developers group grants pod read but NOT kube-system secrets.
	forbOut, err := e.kubectlKC(kc, kubeHome, "get", "secrets", "-n", "kube-system")
	if err == nil {
		t.Fatalf("get secrets -n kube-system should be Forbidden, but succeeded:\n%s", forbOut)
	}
	if !strings.Contains(strings.ToLower(forbOut), "forbidden") {
		t.Fatalf("expected a Forbidden error, got:\n%s", forbOut)
	}

	// Recording lands: admin audits it. Per the per-connection model each kubectl
	// invocation is its own recording object, so the pods read (200) and the
	// forbidden secrets read (403) land in SEPARATE recordings — aggregate all
	// completed recordings for the asset and assert both outcomes appear.
	tmpDir := t.TempDir()
	var agg string
	recDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(recDeadline) {
		list := e.asActor(t, "admin", "recordings", "list", "--asset", assetID, "-o", "json")
		agg = e.downloadAllRecordings(t, list, tmpDir)
		if strings.Contains(agg, `"resource":"pods"`) &&
			strings.Contains(agg, `"resource":"secrets"`) && strings.Contains(agg, `"code":403`) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	// A pods read that succeeded and the forbidden secrets read (403).
	if !strings.Contains(agg, `"resource":"pods"`) {
		t.Fatalf("no recording captured a pods read:\n%s", agg)
	}
	if !strings.Contains(agg, `"resource":"secrets"`) || !strings.Contains(agg, `"code":403`) {
		t.Fatalf("no recording captured the forbidden secrets read (code 403):\n%s", agg)
	}
}

// downloadAllRecordings downloads every completed recording in a `recordings list
// -o json` blob and returns their concatenated NDJSON.
func (e *env) downloadAllRecordings(t *testing.T, listJSON, dir string) string {
	t.Helper()
	var recs []struct {
		SessionID string `json:"sessionId"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal([]byte(listJSON), &recs); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, r := range recs {
		if r.Status != "completed" {
			continue
		}
		p := filepath.Join(dir, r.SessionID+".ndjson")
		e.asActor(t, "admin", "recordings", "download", r.SessionID, "--file", p)
		b, err := os.ReadFile(p) // #nosec G304 -- test-controlled fixture path
		if err == nil {
			sb.Write(b)
		}
	}
	return sb.String()
}

// deployAgent creates the enrollment-token Secret and applies the agent workload,
// then waits for it to become Ready.
func (e *env) deployAgent(t *testing.T, token string) {
	t.Helper()
	// Recreate the Secret (idempotent across reruns).
	_ = exec.Command("kubectl", "delete", "secret", "jumpgate-agent-enrollment", "--ignore-not-found").Run()
	e.kubectl(t, "create", "secret", "generic", "jumpgate-agent-enrollment",
		"--from-literal=token="+token)
	manifest := filepath.Join("..", "env", "testworkload", "k8s-agent.yaml")
	// Force a fresh pod (new emptyDir) so a rerun re-enrolls with the new token.
	e.kubectl(t, "delete", "-f", manifest, "--ignore-not-found")
	e.kubectl(t, "apply", "-f", manifest)
	e.kubectl(t, "rollout", "status", "deploy/jumpgate-k8s-agent", "--timeout=150s")
}

// teardownAgent removes the per-test agent pod + enrollment Secret.
func (e *env) teardownAgent() {
	manifest := filepath.Join("..", "env", "testworkload", "k8s-agent.yaml")
	_ = exec.Command("kubectl", "delete", "-f", manifest, "--ignore-not-found").Run()
	_ = exec.Command("kubectl", "delete", "secret", "jumpgate-agent-enrollment", "--ignore-not-found").Run()
}

// dumpAgent prints agent pod state + logs on failure for diagnosis.
func (e *env) dumpAgent(t *testing.T) {
	t.Helper()
	out, _ := exec.Command("kubectl", "get", "pods", "-l", "app=jumpgate-k8s-agent", "-o", "wide").CombinedOutput()
	t.Logf("agent pods:\n%s", out)
	logs, _ := exec.Command("kubectl", "logs", "deploy/jumpgate-k8s-agent", "--tail=50").CombinedOutput()
	t.Logf("agent logs:\n%s", logs)
	blogs, _ := exec.Command("kubectl", "logs", "deploy/jumpgate-k8s-broker", "--tail=50").CombinedOutput()
	t.Logf("broker logs:\n%s", blogs)
}

// k8sKubeconfigTmpl is a test-runnable kubeconfig: the exec plugin is the absolute
// CLI binary invoked with the k8s-alice context + a private HOME/XDG so the token
// cache doesn't touch the developer's home dir.
const k8sKubeconfigTmpl = `apiVersion: v1
kind: Config
clusters:
- name: jg
  cluster:
    server: https://localhost:8443
    insecure-skip-tls-verify: true
contexts:
- name: jg
  context:
    cluster: jg
    user: jg
current-context: jg
users:
- name: jg
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: %q
      args: ["--context", "k8s-alice", "k8s", "auth", %q]
      env:
      - name: XDG_CONFIG_HOME
        value: %q
      - name: HOME
        value: %q
      interactiveMode: Never
`

// writeK8sKubeconfig renders the test kubeconfig into home and returns its path.
func (e *env) writeK8sKubeconfig(t *testing.T, assetRef, home string) string {
	t.Helper()
	kc := filepath.Join(home, "kubeconfig.yaml")
	content := fmt.Sprintf(k8sKubeconfigTmpl, e.jgBin, assetRef, e.configDir, home)
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return kc
}

// kubectlKC runs kubectl with the given kubeconfig, returning combined output and
// the error (so callers can assert success OR the expected Forbidden failure). HOME
// is set so the exec plugin's token cache lives under the test's temp dir.
func (e *env) kubectlKC(kubeconfig, home string, args ...string) (string, error) {
	full := append([]string{"--kubeconfig", kubeconfig}, args...)
	cmd := exec.Command("kubectl", full...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
