package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAuthzVisibility drives the real CLI to prove the authorization model's
// visibility and isolation guarantees end-to-end: a user sees and reaches ONLY
// what they are entitled to, and cross-tenant topology never leaks. It builds two
// sibling teams (folders az-a and az-b, each with one SSH asset) and three actors:
// alice (standing access in az-a), bob (standing access in az-b), and nomad (no
// roles at all).
//
// It complements TestScenario (the happy-path request→approve→connect flow) with
// the negative space: empty catalogs, per-tenant scoping, and existence-hiding.
func TestAuthzVisibility(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	e := shared

	folderA := e.name("az-a")
	folderB := e.name("az-b")
	roleA := "viewer." + folderA // folder-scoped role, DNS-addressed
	roleB := "viewer." + folderB
	boxA := e.name("box-a") + "." + folderA // DNS path
	boxB := e.name("box-b") + "." + folderB
	aliceEmail := e.name("az-alice") + "@demo.test"
	bobEmail := e.name("az-bob") + "@demo.test"
	nomadEmail := e.name("az-nomad") + "@demo.test"

	t.Run("setup", func(t *testing.T) {
		e.exportMeshCA(t)
		e.login(t, "admin", adminEmail, adminPass)

		// Two sibling teams, each with one SSH asset.
		e.asActor(t, "admin", "folders", "create", folderA)
		e.asActor(t, "admin", "folders", "create", folderB)
		e.asActor(t, "admin", "assets", "ssh", "create", e.name("box-a"),
			"--folder", folderA, "--target", "ssh-target.default.svc.cluster.local:22", "--login", "demo")
		e.asActor(t, "admin", "assets", "ssh", "create", e.name("box-b"),
			"--folder", folderB, "--target", "ssh-target.default.svc.cluster.local:22", "--login", "demo")

		// A per-team viewer role granting the demo login, scoped to its folder.
		e.asActor(t, "admin", "roles", "create", "viewer", "--folder", folderA, "--capability", "ssh:login:demo")
		e.asActor(t, "admin", "roles", "create", "viewer", "--folder", folderB, "--capability", "ssh:login:demo")

		// Actors. alice gets standing access in az-a, bob in az-b, nomad nothing.
		e.asActor(t, "admin", "users", "create", aliceEmail, "--name", "AZAlice", "--password", alicePass)
		e.asActor(t, "admin", "users", "create", bobEmail, "--name", "AZBob", "--password", bobPass)
		e.asActor(t, "admin", "users", "create", nomadEmail, "--name", "AZNomad", "--password", danaPass)

		e.asActor(t, "admin", "bindings", "create", "--role", roleA, "--user", aliceEmail, "--asset", boxA)
		e.asActor(t, "admin", "bindings", "create", "--role", roleB, "--user", bobEmail, "--asset", boxB)

		e.login(t, "az-alice", aliceEmail, alicePass)
		e.login(t, "az-bob", bobEmail, bobPass)
		e.login(t, "az-nomad", nomadEmail, danaPass)
	})

	t.Run("nomad_sees_empty_catalog", func(t *testing.T) {
		// --cascade so the full tree is walked; a capless caller gets an empty list,
		// not PermissionDenied — catalog browse is visibility-filtered, not cap-gated.
		out := e.asActor(t, "az-nomad", "assets", "list", "--cascade", "-o", "json")
		if strings.Contains(out, boxA) || strings.Contains(out, boxB) {
			t.Fatalf("nomad (no roles) must see an empty catalog, got:\n%s", out)
		}
	})

	t.Run("alice_sees_only_team_a", func(t *testing.T) {
		// --cascade so assets nested inside az-a / az-b are included. Without it the
		// root-only browse returns nothing (all assets live inside named folders).
		out := e.asActor(t, "az-alice", "assets", "list", "--cascade", "-o", "json")
		if !strings.Contains(out, boxA) {
			t.Errorf("alice should see her own asset %s:\n%s", boxA, out)
		}
		if strings.Contains(out, boxB) {
			t.Errorf("alice must NOT see the other team's asset %s:\n%s", boxB, out)
		}
	})

	t.Run("bob_sees_only_team_b", func(t *testing.T) {
		// --cascade for the same reason as alice_sees_only_team_a above.
		out := e.asActor(t, "az-bob", "assets", "list", "--cascade", "-o", "json")
		if !strings.Contains(out, boxB) {
			t.Errorf("bob should see his own asset %s:\n%s", boxB, out)
		}
		if strings.Contains(out, boxA) {
			t.Errorf("bob must NOT see the other team's asset %s:\n%s", boxA, out)
		}
	})

	t.Run("alice_can_use_her_own_asset", func(t *testing.T) {
		// Positive control: alice resolves and inspects her own asset (Active tier).
		e.asActor(t, "az-alice", "assets", "get", boxA)
	})

	t.Run("cross_team_is_invisible_and_denied", func(t *testing.T) {
		// Existence-hiding: alice cannot see, resolve, request, or connect to the
		// other team's asset — each attempt fails (NotFound/denied), and none of them
		// reveal that box-b exists.
		e.asActorFails(t, "az-alice", "assets", "get", boxB)
		e.asActorFails(t, "az-alice", "access", "request", "demo@"+boxB, "--role", roleB, "--duration", "1h", "--reason", "probe")
		e.asActorFails(t, "az-alice", "connect", "demo@"+boxB)
		// Symmetric: nomad cannot reach alice's asset either.
		e.asActorFails(t, "az-nomad", "assets", "get", boxA)
		e.asActorFails(t, "az-nomad", "connect", "demo@"+boxA)
	})

	t.Run("non_admin_cannot_administer", func(t *testing.T) {
		// A normal user with only data-plane access holds no management capability:
		// creating folders/roles/users and listing all bindings are all denied.
		e.asActorFails(t, "az-alice", "folders", "create", e.name("az-alice-folder"))
		e.asActorFails(t, "az-alice", "roles", "create", "sneaky", "--folder", folderA, "--capability", "ssh:login:root")
		e.asActorFails(t, "az-alice", "users", "create", e.name("az-mallory")+"@demo.test", "--name", "M", "--password", danaPass)
		e.asActorFails(t, "az-alice", "bindings", "list")
	})

	t.Run("catalog_browse_visibility_subset", func(t *testing.T) {
		// Catalog browse is visibility-filtered (not cap-gated): the admin sees all
		// assets it manages; a data-plane user sees only the assets it can reach. The
		// per-user view must be a strict subset of the admin view, and must never be
		// empty when the user has standing access.
		//
		// Collect asset ids from each actor's cascade list.
		assetIDs := func(listJSON string) map[string]bool {
			var items []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal([]byte(listJSON), &items); err != nil {
				return map[string]bool{}
			}
			m := make(map[string]bool, len(items))
			for _, it := range items {
				if it.ID != "" {
					m[it.ID] = true
				}
			}
			return m
		}

		adminOut := e.asActor(t, "admin", "assets", "list", "--cascade", "-o", "json")
		aliceOut := e.asActor(t, "az-alice", "assets", "list", "--cascade", "-o", "json")
		bobOut := e.asActor(t, "az-bob", "assets", "list", "--cascade", "-o", "json")

		adminIDs := assetIDs(adminOut)
		aliceIDs := assetIDs(aliceOut)
		bobIDs := assetIDs(bobOut)

		// alice's view must be non-empty (she has standing access).
		if len(aliceIDs) == 0 {
			t.Error("alice's cascade asset list is empty but she has standing access")
		}
		// Every asset alice or bob sees must also appear in admin's view.
		for id := range aliceIDs {
			if !adminIDs[id] {
				t.Errorf("alice sees asset %s that admin does not — catalog isolation broken", id)
			}
		}
		for id := range bobIDs {
			if !adminIDs[id] {
				t.Errorf("bob sees asset %s that admin does not — catalog isolation broken", id)
			}
		}
		// alice and bob's views must be disjoint (different teams, no shared assets).
		for id := range aliceIDs {
			if bobIDs[id] {
				t.Errorf("asset %s appears in both alice's and bob's view — tenant isolation broken", id)
			}
		}
	})
}
