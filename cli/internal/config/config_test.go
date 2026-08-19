package config

import (
	"os"
	"path/filepath"
	"testing"
)

// isolate points UserConfigDir at a temp dir and clears the config env vars so
// each test starts from a clean, controlled state.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(envWardenAddr, "")
	t.Setenv(envCAFile, "")
	t.Setenv(envToken, "")
}

func TestLoadFileMissingReturnsEmpty(t *testing.T) {
	isolate(t)
	f, err := LoadFile()
	if err != nil {
		t.Fatalf("LoadFile on missing file: %v", err)
	}
	if f.CurrentContext != "" || len(f.Contexts) != 0 {
		t.Fatalf("expected empty File, got %+v", f)
	}
}

func TestFileSaveLoadRoundTrip(t *testing.T) {
	isolate(t)
	want := File{
		CurrentContext: "default",
		Contexts: map[string]Context{
			"default": {WardenAddr: "http://localhost:8080", CAFile: "/etc/ca.pem", Token: "tok-abc", IsAdmin: true},
		},
	}
	if err := want.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadFile()
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got.CurrentContext != want.CurrentContext || got.Contexts["default"] != want.Contexts["default"] {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestSaveFilePerms(t *testing.T) {
	isolate(t)
	f := File{Contexts: map[string]Context{"default": {Token: "secret"}}}
	if err := f.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config perms = %o, want 600", perm)
	}
}

func TestLoadFileMalformedReturnsError(t *testing.T) {
	isolate(t)
	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.MkdirAll(path[:len(path)-len("/config.json")], 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadFile(); err == nil {
		t.Fatal("expected error for malformed config, got nil")
	}
}

func TestMigrateFlatConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // os.UserConfigDir honors XDG_CONFIG_HOME on linux
	p := filepath.Join(dir, "jumpgate", "config.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"warden_addr":"http://w","ca_file":"/ca","token":"tok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile()
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if f.CurrentContext != "default" {
		t.Fatalf("current=%q", f.CurrentContext)
	}
	ctx, ok := f.Contexts["default"]
	if !ok || ctx.Token != "tok" || ctx.WardenAddr != "http://w" || ctx.CAFile != "/ca" {
		t.Fatalf("migrated context wrong: %+v ok=%v", ctx, ok)
	}
}

func TestResolvePrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	f := File{CurrentContext: "a", Contexts: map[string]Context{"a": {WardenAddr: "http://file", Token: "ftok"}}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JUMPGATE_TOKEN", "etok") // env beats file
	got, err := Resolve("", Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if got.WardenAddr != "http://file" || got.Token != "etok" {
		t.Fatalf("resolve=%+v", got)
	}
	got, _ = Resolve("", Overrides{Token: "flagtok"}) // flag beats env
	if got.Token != "flagtok" {
		t.Fatalf("flag precedence: %q", got.Token)
	}
}

func TestUseContextUnknown(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	f := File{Contexts: map[string]Context{}}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if err := UseContext("nope"); err == nil {
		t.Fatal("want error for unknown context")
	}
}

func TestUpsertContextRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := UpsertContext("bob", Context{WardenAddr: "http://w", Token: "t", IsAdmin: false}, true); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if f.CurrentContext != "bob" || f.Contexts["bob"].Token != "t" {
		t.Fatalf("f=%+v", f)
	}
}
