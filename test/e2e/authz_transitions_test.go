package e2e

import (
	"strings"
	"testing"
)

// TestAuthzGrantTransitions proves that each authorization primitive is
// LOAD-BEARING: for a standing binding, a request policy, an approver subject, and
// a management capability, the relevant action is DENIED before the grant exists
// and the SAME action SUCCEEDS only after an admin adds it. This catches
// default-open regressions and "the permission wasn't actually the thing that
// enabled it" bugs that a steady-state test (TestAuthzVisibility) cannot.
//
// The subtests are ordered and share state: box visibility is established by the
// binding arc, the pending request by the policy arc is approved by the approver
// arc.
func TestAuthzGrantTransitions(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	e := shared
	e.reset(t)

	folder := e.name("tr")
	boxName := e.name("tr-box")
	boxPath := boxName + "." + folder
	deployRoleRef := "tr-deploy." + folder // folder-scoped role, bound standing (arc 1)
	grp := e.name("tr-grp")
	userEmail := e.name("tr-user") + "@demo.test"
	approverEmail := e.name("tr-approver") + "@demo.test"
	mgrEmail := e.name("tr-mgr") + "@demo.test"

	var folderID, reqRoleID, requestID string

	t.Run("setup", func(t *testing.T) {
		e.exportMeshCA(t)
		e.login(t, "admin", adminEmail, adminPass)

		folderID = jsonID(e.asActor(t, "admin", "folders", "create", folder, "-o", "json"))
		if folderID == "" {
			t.Fatal("no folder id")
		}
		assetOut := e.asActor(t, "admin", "assets", "ssh", "create", boxName,
			"--folder", folder, "--target", "ssh-target.default.svc.cluster.local:22", "--login", "deploy", "-o", "json")
		assetPath := jsonField(assetOut, "path")
		// Provision the CA target's accepted principal for this asset (append, so it
		// coexists with other suites' principals on the shared ssh-target).
		e.kubectl(t, "exec", "deploy/ssh-target", "--", "sh", "-c",
			"mkdir -p /etc/ssh/auth_principals && printf 'deploy@%s\\n' '"+assetPath+"' >> /etc/ssh/auth_principals/deploy")

		// A role bound standing in arc 1 (grants the deploy login) and a DISTINCT
		// role made requestable in arc 2 (never bound, so it stays inactive until
		// requested+approved).
		e.asActor(t, "admin", "roles", "create", "tr-deploy", "--folder", folder, "--capability", "ssh:login:deploy")
		reqRoleID = jsonID(e.asActor(t, "admin", "roles", "create", "tr-req", "--folder", folder, "--capability", "ssh:login:deploy", "-o", "json"))
		if reqRoleID == "" {
			t.Fatal("no requestable role id")
		}

		e.asActor(t, "admin", "users", "create", userEmail, "--name", "TrUser", "--password", alicePass)
		e.asActor(t, "admin", "users", "create", approverEmail, "--name", "TrApprover", "--password", bobPass)
		e.asActor(t, "admin", "users", "create", mgrEmail, "--name", "TrMgr", "--password", danaPass)
		e.asActor(t, "admin", "groups", "create", grp)
		e.asActor(t, "admin", "groups", "add-member", grp, userEmail)
		e.asActor(t, "admin", "groups", "add-member", grp, approverEmail)

		e.login(t, "tr-user", userEmail, alicePass)
		e.login(t, "tr-approver", approverEmail, bobPass)
		e.login(t, "tr-mgr", mgrEmail, danaPass)
	})

	// Arc 1: a standing binding turns an invisible asset into a usable one.
	t.Run("standing_binding_enables_visibility_and_connect", func(t *testing.T) {
		// Before: no binding → the asset is invisible and unreachable.
		e.asActorFails(t, "tr-user", "assets", "get", boxPath)
		e.asActorFails(t, "tr-user", "connect", "deploy@"+boxPath, "--ca", e.meshCA)

		// Grant: bind the deploy role to the user's group at the asset.
		e.asActor(t, "admin", "bindings", "create", "--role", deployRoleRef, "--group", grp, "--asset", boxPath)

		// After: the same user now sees the asset AND can open a session on it.
		e.asActor(t, "tr-user", "assets", "get", boxPath)
		out := e.connectWithStdin(t, "tr-user", "deploy@"+boxPath, "echo "+marker+"; exit\n")
		if !strings.Contains(out, marker) {
			t.Fatalf("connect after binding did not run the command:\n%s", out)
		}
	})

	// Arc 2: a request policy turns an un-requestable role into a requestable one.
	t.Run("request_policy_enables_requesting", func(t *testing.T) {
		// Before: no policy for tr-req → requesting it is refused (not requestable).
		e.asActorFails(t, "tr-user", "access", "request", "deploy@"+boxPath,
			"--role", reqRoleID, "--duration", "1h", "--reason", "probe")

		// Grant: make tr-req requestable at the asset, with the group as requester.
		e.asActor(t, "admin", "policies", "create",
			"--name", "tr-pol", "--request-role", reqRoleID, "--asset", boxPath, "--min-approvals", "1")
		e.asActor(t, "admin", "policies", "add-subject", "tr-pol@"+boxPath, "--kind", "requester", "--group", grp)

		// After: the same request now opens a pending request.
		reqOut := e.asActor(t, "tr-user", "access", "request", "deploy@"+boxPath,
			"--role", reqRoleID, "--duration", "1h", "--reason", "probe", "-o", "json")
		requestID = jsonID(reqOut)
		if requestID == "" {
			t.Fatalf("no request id after policy:\n%s", reqOut)
		}
	})

	// Arc 3: an approver subject turns a bystander into someone who can approve.
	t.Run("approver_subject_enables_approval", func(t *testing.T) {
		if requestID == "" {
			t.Skip("no pending request from arc 2")
		}
		// Before: the approver is not on the policy's approver set → cannot approve.
		e.asActorFails(t, "tr-approver", "access", "approve", requestID)

		// Grant: add the group as an approver subject.
		e.asActor(t, "admin", "policies", "add-subject", "tr-pol@"+boxPath, "--kind", "approver", "--group", grp)

		// After: the approver can approve, minting the requester's grant.
		e.asActor(t, "tr-approver", "access", "approve", requestID)
		grants := e.asActor(t, "tr-user", "access", "grants", "-o", "json")
		if !strings.Contains(grants, reqRoleID) {
			t.Fatalf("approved request did not mint a grant for role %s:\n%s", reqRoleID, grants)
		}
	})

	// Arc 4: a scoped management capability turns a normal user into a folder admin
	// — for that folder only.
	t.Run("management_capability_enables_administration", func(t *testing.T) {
		// Before: no capability → cannot create a folder anywhere.
		e.asActorFails(t, "tr-mgr", "folders", "create", e.name("tr-sub"), "--parent", folderID)

		// Grant: a role carrying catalog:folder:{create,read}, bound at the folder.
		// The role is global (no --folder), so its name must be suffixed to stay
		// unique across repeat runs on a kept cluster.
		e.asActor(t, "admin", "roles", "create", e.name("tr-folderadmin"),
			"--capability", "catalog:folder:create", "--capability", "catalog:folder:read")
		e.asActor(t, "admin", "bindings", "create", "--role", e.name("tr-folderadmin"), "--user", mgrEmail, "--folder", folder)

		// After: the same command succeeds within the delegated folder...
		e.asActor(t, "tr-mgr", "folders", "create", e.name("tr-sub"), "--parent", folderID)
		// ...but the capability does NOT leak to the global scope (a top-level
		// folder needs the capability held globally, which the user does not have).
		e.asActorFails(t, "tr-mgr", "folders", "create", e.name("tr-top"))
	})
}
