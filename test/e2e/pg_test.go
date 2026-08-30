package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPostgresPassword drives the postgres password-login connect path end-to-end:
// onboard a postgres asset with a password login, grant an actor `db:login:app` via
// a standing binding (the postgres analog of TestScenario's act3b SSH-password
// case — a direct role binding, no JIT request/approve dance), connect through the
// CLI's local loopback proxy running `psql -c 'select 1'`, and assert both the query
// result and a completed, statement-containing recording.
func TestPostgresPassword(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql not installed")
	}
	e := shared
	e.reset(t)

	folder := e.name("pg-demo")
	pgUserEmail := e.name("pg-alice") + "@demo.test"

	e.exportMeshCA(t)
	e.login(t, "admin", adminEmail, adminPass)

	e.asActor(t, "admin", "folders", "create", folder)

	// Onboard: create the asset (no inline mtls login), then set a password login —
	// mirrors act0b's SSH password-box (`assets ssh create` then `assets ssh login
	// set --kind password --password-stdin`).
	assetOut := e.asActor(t, "admin", "assets", "pg", "create", e.name("pg-box"),
		"--folder", folder,
		"--target", "pg-target.default.svc.cluster.local:5432",
		"--database", "appdb", "-o", "json")
	assetID := jsonID(assetOut)
	if assetID == "" {
		t.Fatalf("no asset id:\n%s", assetOut)
	}
	assetPath := jsonField(assetOut, "path")
	if assetPath == "" {
		t.Fatalf("no asset path in create output:\n%s", assetOut)
	}

	e.asActorStdin(t, "admin", "app-e2e-pw\n",
		"assets", "pg", "login", "set", assetPath,
		"--role", "app", "--kind", "password", "--password-stdin")

	// A folder-scoped role carrying db:login:app, bound directly to the connecting
	// actor on the asset — a standing binding, exactly like act0b's ssh-demo role +
	// per-asset binding for the password/key connect cases.
	e.asActor(t, "admin", "roles", "create", e.name("pg-app"),
		"--folder", folder, "--capability", "db:login:app")
	e.asActor(t, "admin", "users", "create", pgUserEmail, "--name", "PGAlice", "--password", alicePass)

	roleRef := e.name("pg-app") + "." + folder
	e.asActor(t, "admin", "bindings", "create",
		"--role", roleRef, "--user", pgUserEmail, "--asset", assetPath)

	e.login(t, "pg-alice", pgUserEmail, alicePass)

	out := e.connectPgExec(t, "pg-alice", "app@"+assetPath, "psql", "-c", "select 1")
	if !strings.Contains(out, "1") {
		t.Fatalf("psql output missing the query result:\n%s", out)
	}

	// Recordings are admin-only, so the admin acts as auditor, exactly as
	// act4_auditor_verifies_recording does for the SSH scenario.
	var sessionID string
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		list := e.asActor(t, "admin", "recordings", "list", "--asset", assetID, "-o", "json")
		if id := completedSessionID(list); id != "" {
			sessionID = id
			break
		}
		time.Sleep(1 * time.Second)
	}
	if sessionID == "" {
		t.Fatal("no completed recording appeared for the postgres asset within 45s")
	}

	recPath := filepath.Join(t.TempDir(), "rec.ndjson")
	e.asActor(t, "admin", "recordings", "download", sessionID, "--file", recPath)
	data, err := os.ReadFile(recPath) // #nosec G304 -- test-controlled fixture path
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	if !strings.Contains(string(data), "select 1") {
		t.Fatal("recording does not contain the statement alice ran")
	}
}

// TestPostgresMtls mirrors TestPostgresPassword for the mtls login kind: the
// broker mints a short-lived client cert instead of injecting a stored
// secret, so the login is set with no --password-stdin. Uses its own folder
// and asset to stay independent of the password test.
func TestPostgresMtls(t *testing.T) {
	if shared == nil {
		t.Skip("no live cluster (set JUMPGATE_E2E=1)")
	}
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql not installed")
	}
	e := shared
	e.reset(t)

	folder := e.name("pg-mtls-demo")
	pgUserEmail := e.name("pg-bob") + "@demo.test"

	e.exportMeshCA(t)
	e.login(t, "admin", adminEmail, adminPass)

	e.asActor(t, "admin", "folders", "create", folder)

	assetOut := e.asActor(t, "admin", "assets", "pg", "create", e.name("pg-box-mtls"),
		"--folder", folder,
		"--target", "pg-target.default.svc.cluster.local:5432",
		"--database", "appdb", "-o", "json")
	assetID := jsonID(assetOut)
	if assetID == "" {
		t.Fatalf("no asset id:\n%s", assetOut)
	}
	assetPath := jsonField(assetOut, "path")
	if assetPath == "" {
		t.Fatalf("no asset path in create output:\n%s", assetOut)
	}

	// mtls needs no stored secret — the broker mints the client cert.
	e.asActor(t, "admin", "assets", "pg", "login", "set", assetPath,
		"--role", "mtlsuser", "--kind", "mtls")

	e.asActor(t, "admin", "roles", "create", e.name("pg-mtls"),
		"--folder", folder, "--capability", "db:login:mtlsuser")
	e.asActor(t, "admin", "users", "create", pgUserEmail, "--name", "PGBob", "--password", alicePass)

	roleRef := e.name("pg-mtls") + "." + folder
	e.asActor(t, "admin", "bindings", "create",
		"--role", roleRef, "--user", pgUserEmail, "--asset", assetPath)

	e.login(t, "pg-bob", pgUserEmail, alicePass)

	out := e.connectPgExec(t, "pg-bob", "mtlsuser@"+assetPath, "psql", "-c", "select 1")
	if !strings.Contains(out, "1") {
		t.Fatalf("psql output missing the query result:\n%s", out)
	}

	// Recordings are admin-only, so the admin acts as auditor, exactly as
	// act4_auditor_verifies_recording does for the SSH scenario.
	var sessionID string
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		list := e.asActor(t, "admin", "recordings", "list", "--asset", assetID, "-o", "json")
		if id := completedSessionID(list); id != "" {
			sessionID = id
			break
		}
		time.Sleep(1 * time.Second)
	}
	if sessionID == "" {
		t.Fatal("no completed recording appeared for the postgres asset within 45s")
	}

	recPath := filepath.Join(t.TempDir(), "rec.ndjson")
	e.asActor(t, "admin", "recordings", "download", sessionID, "--file", recPath)
	data, err := os.ReadFile(recPath) // #nosec G304 -- test-controlled fixture path
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	if !strings.Contains(string(data), "select 1") {
		t.Fatal("recording does not contain the statement bob ran")
	}
}
