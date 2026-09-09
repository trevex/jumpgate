package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNetworkPolicyBlocksUnlabeledPod proves the chart's default-deny +
// per-component NetworkPolicy is actually enforced (the e2e cluster runs Cilium,
// which honors NetworkPolicy — kind's default kindnet does not).
//
// The probe pod carries no jumpgate labels, so it is selected by no allow rule.
// It targets the bundled postgres, whose NetworkPolicy admits ingress on 5432 only
// from jumpgate-labeled pods and exposes no NodePort — so it is a genuinely closed
// edge. (warden, gateway and silo:9000 are deliberately open-ingress exposed
// surfaces and would NOT be blocked.) Under Cilium the connection must fail; a
// success means the policy did not bind, and the test fails loudly.
func TestNetworkPolicyBlocksUnlabeledPod(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}

	out, _ := exec.Command("kubectl", "run", "netpol-probe",
		"--rm", "-i", "--restart=Never", "--image=curlimages/curl:8.10.1",
		"--command", "--",
		"curl", "-sS", "--max-time", "5",
		"http://jumpgate-postgres:5432/",
	).CombinedOutput()
	got := string(out)

	// Blocked shows as a curl connect/timeout error. If the edge were open, curl
	// would establish TCP and get an HTTP-level error from postgres (e.g. "Empty
	// reply"/"Recv failure") — none of which match below, so the test would fail.
	if !strings.Contains(got, "imed out") &&
		!strings.Contains(got, "Timeout") &&
		!strings.Contains(got, "Failed to connect") {
		t.Fatalf("expected probe blocked by NetworkPolicy, got: %q", got)
	}
}
