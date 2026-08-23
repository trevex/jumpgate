package e2e

import (
	"strings"
	"testing"
	"time"
)

// Stable object identities the browser story logs in with. These match the
// defaults baked into web/e2e/access-loop.spec.ts. adminEmail/adminPass and the
// alicePass/bobPass/marker consts already exist package-wide (scenario_test.go),
// so only the browser-specific emails are added here.
const (
	uiAliceEmail = "alice@demo.test"
	uiBobEmail   = "bob@demo.test"
)

// TestUISeed provisions the fixtures the browser console e2e drives:
//   - a JIT-requestable asset (demo-box) alice has NO standing access to, gated
//     by a cross-approval request policy where the sre group is both requester
//     and approver — this is what the browser request→approve loop exercises;
//   - a separate standing-access password asset (password-box) that alice
//     connects to via the CLI to produce a COMPLETED recording, so the browser
//     audit view has content to play back without granting standing access to
//     demo-box (which would spoil the JIT flow);
//   - a second JIT-requestable asset (review-box) that alice reaches through an
//     approved grant, producing a grant-attributed recording — the fixture the
//     browser session-review discovery paths (subject grant card, approver
//     Reviewable list, per-asset filter) play back.
//
// It assumes a fresh cluster (the make ui-e2e path runs it right after kind-up).
// Object creation is not idempotent; re-seeding a dirty cluster is expected to
// fail. Bring a fresh kind-up to iterate.
func TestUISeed(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	e := shared

	e.exportMeshCA(t)
	e.login(t, "admin", adminEmail, adminPass)

	// ── Governance tree: a demo folder holding the requestable asset ──
	e.asActor(t, "admin", "folders", "create", "demo")

	assetOut := e.asActor(t, "admin", "assets", "ssh", "create", "demo-box",
		"--folder", "demo",
		"--target", "ssh-target.default.svc.cluster.local:22",
		"--login", "deploy", "-o", "json")
	assetID := jsonID(assetOut)
	if assetID == "" {
		t.Fatalf("no demo-box asset id:\n%s", assetOut)
	}
	assetPath := jsonField(assetOut, "path")
	if assetPath == "" {
		t.Fatalf("no demo-box asset path:\n%s", assetOut)
	}
	// Provision the target's accepted CA principal from the onboarded path — the
	// operator step a real host onboarding performs.
	e.kubectl(t, "exec", "deploy/ssh-target", "--",
		"sh", "-c",
		"mkdir -p /etc/ssh/auth_principals && printf 'deploy@%s\\n' '"+assetPath+"' > /etc/ssh/auth_principals/deploy")

	roleOut := e.asActor(t, "admin", "roles", "create", "ssh-deploy",
		"--folder", "demo",
		"--capability", "ssh:login:deploy", "-o", "json")
	roleID := jsonID(roleOut)
	if roleID == "" {
		t.Fatalf("no ssh-deploy role id:\n%s", roleOut)
	}

	// ── Actors: alice + bob in an sre group (cross-approval via membership) ──
	e.asActor(t, "admin", "users", "create", uiAliceEmail, "--name", "Alice", "--password", alicePass)
	e.asActor(t, "admin", "users", "create", uiBobEmail, "--name", "Bob", "--password", bobPass)
	e.asActor(t, "admin", "groups", "create", "sre")
	e.asActor(t, "admin", "groups", "add-member", "sre", uiAliceEmail)
	e.asActor(t, "admin", "groups", "add-member", "sre", uiBobEmail)

	// ── Cross-approval request policy: ssh-deploy is REQUESTABLE at demo-box,
	// not a standing binding. Any sre member requests; any other approves. ──
	caPath := "demo-box.demo"
	policyRef := "approve-deploy@" + caPath
	e.asActor(t, "admin", "policies", "create",
		"--name", "approve-deploy",
		"--request-role", roleID,
		"--asset", caPath,
		"--min-approvals", "1")
	e.asActor(t, "admin", "policies", "add-subject", policyRef, "--kind", "requester", "--group", "sre")
	e.asActor(t, "admin", "policies", "add-subject", policyRef, "--kind", "approver", "--group", "sre")

	// ── Recording fixture: a SEPARATE standing-access password asset. Standing
	// access here keeps demo-box purely JIT so the browser request flow is real. ──
	demoRoleOut := e.asActor(t, "admin", "roles", "create", "ssh-demo",
		"--folder", "demo",
		"--capability", "ssh:login:demo", "-o", "json")
	demoRoleID := jsonID(demoRoleOut)
	if demoRoleID == "" {
		t.Fatalf("no ssh-demo role id:\n%s", demoRoleOut)
	}

	pwOut := e.asActor(t, "admin", "assets", "ssh", "create", "password-box",
		"--folder", "demo",
		"--target", "ssh-target-password.default.svc.cluster.local:22", "-o", "json")
	pwAssetID := jsonID(pwOut)
	if pwAssetID == "" {
		t.Fatalf("no password-box asset id:\n%s", pwOut)
	}
	pwPath := "password-box.demo"
	e.asActorStdin(t, "admin", "demo-password-123\n",
		"assets", "ssh", "login", "set", pwPath,
		"--login", "demo", "--kind", "password", "--password-stdin")

	// Standing binding for sre on password-box. ssh-demo is folder-scoped, so
	// address it by its namespaced DNS name.
	e.asActor(t, "admin", "bindings", "create",
		"--role", "ssh-demo.demo", "--group", "sre", "--asset", pwPath)

	// ── Folder-cascade fixture: an asset reachable ONLY via a FOLDER-scoped
	// binding (no asset-scoped binding), proving connect authz cascades
	// folder→asset. A GLOBAL ssh:login role is bound at the `cascade` folder to
	// the sre group; cascade-box lives in that folder with no binding of its own,
	// so alice (in sre) can connect to it only through the folder cascade. ──
	e.asActor(t, "admin", "roles", "create", "folderssh", "--capability", "ssh:login:demo")
	e.asActor(t, "admin", "folders", "create", "cascade")
	e.asActor(t, "admin", "assets", "ssh", "create", "cascade-box",
		"--folder", "cascade",
		"--target", "ssh-target-password.default.svc.cluster.local:22")
	e.asActorStdin(t, "admin", "demo-password-123\n",
		"assets", "ssh", "login", "set", "cascade-box.cascade",
		"--login", "demo", "--kind", "password", "--password-stdin")
	e.asActor(t, "admin", "bindings", "create",
		"--role", "folderssh", "--group", "sre", "--folder", "cascade")

	// ── Produce a recorded session so the browser audit view has content ──
	e.login(t, "alice", uiAliceEmail, alicePass)
	script := "echo " + marker + "; whoami; exit\n"
	out := e.connectWithStdin(t, "alice", "demo@"+pwPath, script)
	if !strings.Contains(out, marker) {
		t.Fatalf("recorded connect missing marker:\n%s", out)
	}

	// Poll until the recording is COMPLETED and visible, so Playwright can play
	// it back the moment it opens the Recordings view.
	deadline := time.Now().Add(60 * time.Second)
	var sessionID string
	for time.Now().Before(deadline) {
		list := e.asActor(t, "admin", "recordings", "list", "--asset", pwAssetID, "-o", "json")
		if id := completedSessionID(list); id != "" {
			sessionID = id
			break
		}
		time.Sleep(1 * time.Second)
	}
	if sessionID == "" {
		t.Fatal("no completed recording appeared for password-box within 60s")
	}

	// ── Grant-attributed recording fixture: a SECOND JIT-requestable asset
	// (review-box) that alice reaches ONLY through an approved grant, so its
	// recording is attributed to that grant (session_recordings.grant_id). This
	// backs the browser session-review discovery paths — the subject's grant
	// card, the approver's Reviewable list, and the per-asset filter. Kept
	// distinct from demo-box so the browser request→approve flow there stays
	// pristine (no pre-existing grant on demo-box). ──
	reviewOut := e.asActor(t, "admin", "assets", "ssh", "create", "review-box",
		"--folder", "demo",
		"--target", "ssh-target.default.svc.cluster.local:22",
		"--login", "deploy", "-o", "json")
	reviewAssetID := jsonID(reviewOut)
	if reviewAssetID == "" {
		t.Fatalf("no review-box asset id:\n%s", reviewOut)
	}
	reviewPath := jsonField(reviewOut, "path")
	if reviewPath == "" {
		t.Fatalf("no review-box asset path:\n%s", reviewOut)
	}
	// Append review-box's host-scoped CA principal to the deploy principals file
	// (demo-box's write above used > and would otherwise clobber it).
	e.kubectl(t, "exec", "deploy/ssh-target", "--",
		"sh", "-c",
		"printf 'deploy@%s\\n' '"+reviewPath+"' >> /etc/ssh/auth_principals/deploy")

	// review-box is JIT-requestable via the same ssh-deploy role under its own
	// cross-approval policy (sre requests and approves).
	reviewPolicyRef := "approve-review@" + reviewPath
	e.asActor(t, "admin", "policies", "create",
		"--name", "approve-review",
		"--request-role", roleID,
		"--asset", reviewPath,
		"--min-approvals", "1")
	e.asActor(t, "admin", "policies", "add-subject", reviewPolicyRef, "--kind", "requester", "--group", "sre")
	e.asActor(t, "admin", "policies", "add-subject", reviewPolicyRef, "--kind", "approver", "--group", "sre")

	// alice requests → bob approves → alice connects over the grant, producing a
	// COMPLETED recording attributed to the resulting grant.
	e.login(t, "alice", uiAliceEmail, alicePass)
	reviewReqOut := e.asActor(t, "alice", "access", "request",
		"deploy@"+reviewPath, "--role", "ssh-deploy", "--duration", "1h",
		"--reason", "e2e: session-review discovery", "-o", "json")
	reviewReqID := jsonID(reviewReqOut)
	if reviewReqID == "" {
		t.Fatalf("no review-box request id:\n%s", reviewReqOut)
	}
	e.login(t, "bob", uiBobEmail, bobPass)
	e.asActor(t, "bob", "access", "approve", reviewReqID)

	e.login(t, "alice", uiAliceEmail, alicePass)
	reviewScript := "echo " + marker + "; whoami; exit\n"
	reviewConn := e.connectWithStdin(t, "alice", "deploy@"+reviewPath, reviewScript)
	if !strings.Contains(reviewConn, marker) {
		t.Fatalf("review-box connect missing marker:\n%s", reviewConn)
	}

	// Poll until review-box's grant-attributed recording is COMPLETED, so the
	// browser can play it back the moment it opens the filtered view.
	reviewDeadline := time.Now().Add(60 * time.Second)
	var reviewSession string
	for time.Now().Before(reviewDeadline) {
		list := e.asActor(t, "admin", "recordings", "list", "--asset", reviewAssetID, "-o", "json")
		if id := completedSessionID(list); id != "" {
			reviewSession = id
			break
		}
		time.Sleep(1 * time.Second)
	}
	if reviewSession == "" {
		t.Fatal("no completed recording appeared for review-box within 60s")
	}
}
