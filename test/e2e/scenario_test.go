package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	demoRoleID                 string
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

		assetOut := e.asActor(t, "admin", "assets", "ssh", "create", e.name("demo-box"),
			"--folder", e.name("demo"),
			"--target", "ssh-target.default.svc.cluster.local:22",
			"--login", "deploy", "-o", "json")
		st.assetID = jsonID(assetOut)
		if st.assetID == "" {
			t.Fatalf("no asset id:\n%s", assetOut)
		}

		assetPath := jsonField(assetOut, "path")
		if assetPath == "" {
			t.Fatalf("no asset path in create output:\n%s", assetOut)
		}
		// Post-onboard provisioning: automation writes the target's accepted
		// principal from the path the onboard command returned. This is the
		// operator step a real deployment performs when creating/onboarding a host.
		e.kubectl(t, "exec", "deploy/ssh-target", "--",
			"sh", "-c",
			"mkdir -p /etc/ssh/auth_principals && printf 'deploy@%s\\n' '"+assetPath+"' > /etc/ssh/auth_principals/deploy")

		roleOut := e.asActor(t, "admin", "roles", "create", e.name("ssh-deploy"),
			"--folder", e.name("demo"),
			"--capability", "ssh:login:deploy", "-o", "json")
		st.roleID = jsonID(roleOut)
		if st.roleID == "" {
			t.Fatalf("no role id:\n%s", roleOut)
		}

		// Two normal users with login passwords. A display name is required.
		e.asActor(t, "admin", "users", "create", st.aliceEmail, "--name", "Alice", "--password", alicePass)
		e.asActor(t, "admin", "users", "create", st.bobEmail, "--name", "Bob", "--password", bobPass)

		// An "sre" group with both users as members. Permissions below are assigned
		// to the group, not the individuals — access flows through group membership.
		e.asActor(t, "admin", "groups", "create", e.name("sre"))
		e.asActor(t, "admin", "groups", "add-member", e.name("sre"), st.aliceEmail)
		e.asActor(t, "admin", "groups", "add-member", e.name("sre"), st.bobEmail)

		caPath := e.name("demo-box") + "." + e.name("demo")
		policyRef := e.name("approve-deploy") + "@" + caPath

		// Request policy: the ssh-deploy role is requestable at the asset scope,
		// requiring one approval. Named so it can be referenced as <name>@<asset-path>.
		e.asActor(t, "admin", "policies", "create",
			"--name", e.name("approve-deploy"),
			"--request-role", st.roleID,
			"--asset", caPath,
			"--min-approvals", "1")
		// The sre group is BOTH requester and approver, so any member can request and
		// any other member can approve — cross-approval via group membership.
		e.asActor(t, "admin", "policies", "add-subject", policyRef, "--kind", "requester", "--group", e.name("sre"))
		e.asActor(t, "admin", "policies", "add-subject", policyRef, "--kind", "approver", "--group", e.name("sre"))
	})

	t.Run("act0b_stored_secret_setup", func(t *testing.T) {
		// A role carrying ssh:login:demo, and two stored-secret assets (password +
		// key) pointing at the dedicated sshd workloads. Alice gets a standing
		// binding to each (no JIT dance for these — the CA path already exercises it).
		roleOut := e.asActor(t, "admin", "roles", "create", e.name("ssh-demo"),
			"--folder", e.name("demo"),
			"--capability", "ssh:login:demo", "-o", "json")
		st.demoRoleID = jsonID(roleOut)
		if st.demoRoleID == "" {
			t.Fatalf("no demo role id:\n%s", roleOut)
		}

		pwPath := e.name("password-box") + "." + e.name("demo")
		keyPath := e.name("key-box") + "." + e.name("demo")

		// Password asset: create (no inline login), then set a password login.
		e.asActor(t, "admin", "assets", "ssh", "create", e.name("password-box"),
			"--folder", e.name("demo"),
			"--target", "ssh-target-password.default.svc.cluster.local:22")
		e.asActorStdin(t, "admin", "demo-password-123\n",
			"assets", "ssh", "login", "set", pwPath,
			"--login", "demo", "--kind", "password", "--password-stdin")

		// Key asset: create, then set a key login from the committed test private key.
		e.asActor(t, "admin", "assets", "ssh", "create", e.name("key-box"),
			"--folder", e.name("demo"),
			"--target", "ssh-target-key.default.svc.cluster.local:22")
		e.asActor(t, "admin", "assets", "ssh", "login", "set", keyPath,
			"--login", "demo", "--kind", "key", "--key-file", "../env/testworkload/demo_key")

		// Standing bindings for the sre group on both assets — admin can resolve
		// them by path once they exist in the catalog. ssh-demo is folder-scoped, so
		// it is addressed by its namespaced DNS name (<role>.<folder-path>); a bare
		// name would resolve as a global role and not be found.
		demoRoleRef := e.name("ssh-demo") + "." + e.name("demo")
		for _, path := range []string{pwPath, keyPath} {
			e.asActor(t, "admin", "bindings", "create",
				"--role", demoRoleRef, "--group", e.name("sre"), "--asset", path)
		}
	})

	t.Run("act1_alice_requests", func(t *testing.T) {
		e.login(t, "alice", st.aliceEmail, alicePass)
		// Discovery: alice sees the requestable role BY NAME on the asset.
		access := e.asActor(t, "alice", "assets", "get", e.name("demo-box")+"."+e.name("demo"), "-o", "json")
		if !strings.Contains(access, e.name("ssh-deploy")) {
			t.Fatalf("alice cannot see the requestable role by name:\n%s", access)
		}
		// Request by asset PATH + role NAME — no ids.
		reqOut := e.asActor(t, "alice", "access", "request",
			"deploy@"+e.name("demo-box")+"."+e.name("demo"),
			"--role", e.name("ssh-deploy"), "--duration", "1h",
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

	t.Run("act3_alice_connects", func(t *testing.T) {
		// The approval produced a time-boxed grant; it should now show up.
		grants := e.asActor(t, "alice", "access", "grants", "-o", "json")
		if !strings.Contains(grants, st.assetID) {
			t.Fatalf("alice has no grant for asset %s:\n%s", st.assetID, grants)
		}
		// With the grant, the asset resolves by name; connect over the tunnel and
		// run a marker command whose output we can later find in the recording.
		script := "echo " + marker + "; hostname; whoami; exit\n"
		out := e.connectWithStdin(t, "alice", "deploy@"+e.name("demo-box")+"."+e.name("demo"), script)
		if !strings.Contains(out, marker) {
			t.Fatalf("connect output missing marker:\n%s", out)
		}
	})

	t.Run("act3b_alice_connects_password", func(t *testing.T) {
		// Standing binding + password login: the worker injects the stored password.
		script := "echo " + marker + "; whoami; exit\n"
		out := e.connectWithStdin(t, "alice", "demo@"+e.name("password-box")+"."+e.name("demo"), script)
		if !strings.Contains(out, marker) {
			t.Fatalf("password connect output missing marker:\n%s", out)
		}
	})

	t.Run("act3c_alice_connects_key", func(t *testing.T) {
		// Standing binding + key login: the worker injects the stored private key.
		script := "echo " + marker + "; whoami; exit\n"
		out := e.connectWithStdin(t, "alice", "demo@"+e.name("key-box")+"."+e.name("demo"), script)
		if !strings.Contains(out, marker) {
			t.Fatalf("key connect output missing marker:\n%s", out)
		}
	})

	t.Run("act4_auditor_verifies_recording", func(t *testing.T) {
		// Recordings are admin-only, so the admin acts as auditor. Filter by this
		// run's asset so we find alice's session, not a leftover from another run.
		var sessionID string
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			list := e.asActor(t, "admin", "recordings", "list", "--asset", st.assetID, "-o", "json")
			if id := completedSessionID(list); id != "" {
				sessionID = id
				break
			}
			time.Sleep(1 * time.Second)
		}
		if sessionID == "" {
			t.Fatal("no completed recording appeared for the asset within 45s")
		}
		castPath := filepath.Join(fixturesDir(t), "recording"+e.suffix+".cast")
		e.asActor(t, "admin", "recordings", "download", sessionID, "--file", castPath)
		data, err := os.ReadFile(castPath) // #nosec G304 -- test-controlled fixture path
		if err != nil {
			t.Fatalf("read recording: %v", err)
		}
		if !strings.Contains(string(data), marker) {
			t.Fatal("recording asciicast does not contain the marker alice typed")
		}
	})
}
