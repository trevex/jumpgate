package e2e

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// shared is initialized by TestMain and used by the scenario. nil means "skip".
var shared *env

func TestMain(m *testing.M) {
	// Fail-safe: only run the live scenario when explicitly enabled AND the warden
	// API is reachable. Without JUMPGATE_E2E the process still runs the pure unit
	// tests (jsonID etc.) and skips anything needing a cluster.
	if os.Getenv("JUMPGATE_E2E") != "1" {
		os.Exit(m.Run())
	}
	// Env requested but nothing listening: make it a loud failure, not a pass.
	conn, err := net.DialTimeout("tcp", "localhost:8080", 3*time.Second)
	if err != nil {
		panic("JUMPGATE_E2E=1 but warden API not reachable at localhost:8080: " + err.Error())
	}
	_ = conn.Close()

	fixtures, err := filepath.Abs(filepath.Join("..", "fixtures"))
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(fixtures, 0o750); err != nil {
		panic(err)
	}
	// Build the CLI once into fixtures. The cli module resolves the warden dependency
	// via its own go.mod replace, so this builds the same in or out of the workspace.
	jgBin := filepath.Join(fixtures, "jumpgate-cli")
	build := exec.Command("go", "build", "-o", jgBin, ".")
	build.Dir = filepath.Join("..", "..", "cli")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		panic("build cli: " + err.Error() + "\n" + string(out))
	}

	configDir := filepath.Join(fixtures, "config")
	_ = os.RemoveAll(configDir)
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		panic(err)
	}
	shared = &env{
		jgBin:     jgBin,
		configDir: configDir,
		meshCA:    filepath.Join(fixtures, "mesh-ca.pem"),
		wardenURL: "http://localhost:8080",
		suffix:    os.Getenv("E2E_SUFFIX"),
	}

	os.Exit(m.Run())
}
