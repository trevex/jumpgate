package e2e

import (
	"strings"
	"testing"
)

const (
	adminEmail = "admin@demo.test"
	adminPass  = "admin-password-1234"
	alicePass  = "alice-password-1234"
	bobPass    = "bob-password-1234"
	marker     = "JUMPGATE_E2E_OK"
)

// scenarioState threads ids captured in Act 0 through the later acts.
type scenarioState struct {
	assetID, roleID, requestID string
	aliceEmail, bobEmail       string
}

// TestScenario runs the 3-actor cross-approval flow against a live test env:
// admin onboards an asset and a cross-approval policy, alice requests, bob
// approves, alice connects and runs a command, and the admin (auditor) verifies
// the recording captured it. Acts 3-4 are appended in a later change.
func TestScenario(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	e := shared
	st := &scenarioState{
		aliceEmail: e.name("alice") + "@demo.test",
		bobEmail:   e.name("bob") + "@demo.test",
	}

	t.Run("act0_admin_setup", func(t *testing.T) {
		e.exportMeshCA(t)
		e.login(t, "admin", adminEmail, adminPass)

		e.asActor(t, "admin", "folders", "create", e.name("demo"))

		assetOut := e.asActor(t, "admin", "assets", "onboard", "ssh", e.name("demo-box"),
			"--folder", e.name("demo"),
			"--target", "ssh-target.default.svc.cluster.local:22",
			"--login", "deploy", "-o", "json")
		st.assetID = jsonID(assetOut)
		if st.assetID == "" {
			t.Fatalf("no asset id:\n%s", assetOut)
		}

		roleOut := e.asActor(t, "admin", "roles", "create", e.name("ssh-deploy"),
			"--capability", "ssh:login:deploy", "-o", "json")
		st.roleID = jsonID(roleOut)
		if st.roleID == "" {
			t.Fatalf("no role id:\n%s", roleOut)
		}

		// Two normal users with login passwords. A display name is required.
		e.asActor(t, "admin", "users", "create", st.aliceEmail, "--name", "Alice", "--password", alicePass)
		e.asActor(t, "admin", "users", "create", st.bobEmail, "--name", "Bob", "--password", bobPass)

		// Request policy: the ssh-deploy role is requestable at the asset scope,
		// requiring one approval.
		polOut := e.asActor(t, "admin", "policies", "create",
			"--request-role", st.roleID,
			"--asset", st.assetID,
			"--min-approvals", "1", "-o", "json")
		polID := jsonID(polOut)
		if polID == "" {
			t.Fatalf("no policy id:\n%s", polOut)
		}
		// Alice and bob are BOTH requester and approver, so either can request and
		// either can approve the other.
		for _, email := range []string{st.aliceEmail, st.bobEmail} {
			e.asActor(t, "admin", "policies", "add-subject", polID, "--kind", "requester", "--user", email)
			e.asActor(t, "admin", "policies", "add-subject", polID, "--kind", "approver", "--user", email)
		}
	})

	t.Run("act1_alice_requests", func(t *testing.T) {
		e.login(t, "alice", st.aliceEmail, alicePass)
		// Request by role id + asset id: a requester need not be able to resolve
		// them by name (the asset is not yet visible to her). The login@ prefix is
		// cosmetic; the role determines the actual login.
		reqOut := e.asActor(t, "alice", "access", "request", "deploy@"+st.assetID,
			"--role", st.roleID, "--duration", "1h",
			"--reason", "need to check the demo box", "-o", "json")
		st.requestID = jsonID(reqOut)
		if st.requestID == "" {
			t.Fatalf("no request id:\n%s", reqOut)
		}
	})

	t.Run("act2_bob_approves", func(t *testing.T) {
		e.login(t, "bob", st.bobEmail, bobPass)
		pending := e.asActor(t, "bob", "access", "list", "--pending-approvals", "-o", "json")
		if !strings.Contains(pending, st.requestID) {
			t.Fatalf("bob's pending approvals missing request %s:\n%s", st.requestID, pending)
		}
		e.asActor(t, "bob", "access", "approve", st.requestID)
	})
}
