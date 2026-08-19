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

func TestLoadMissingFileReturnsZeroConfig(t *testing.T) {
	isolate(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if (c != Config{}) {
		t.Fatalf("expected zero Config, got %+v", c)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	isolate(t)
	want := Config{WardenAddr: "http://localhost:8080", CAFile: "/etc/ca.pem", Token: "tok-abc"}
	if err := want.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestSaveFilePerms(t *testing.T) {
	isolate(t)
	if err := (Config{Token: "secret"}).Save(); err != nil {
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

func TestLoadMalformedFileReturnsError(t *testing.T) {
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
	if _, err := Load(); err == nil {
		t.Fatal("expected error for malformed config, got nil")
	}
}

func TestOverlayPrecedence(t *testing.T) {
	isolate(t)
	file := Config{WardenAddr: "http://file-addr", CAFile: "/file/ca", Token: "file-token"}

	// File only: no env, no flags -> file values survive.
	if got := file.Overlay(Config{}); got != file {
		t.Fatalf("file-only overlay = %+v, want %+v", got, file)
	}

	// Env overrides file.
	t.Setenv(envWardenAddr, "http://env-addr")
	t.Setenv(envToken, "env-token")
	got := file.Overlay(Config{})
	if got.WardenAddr != "http://env-addr" {
		t.Fatalf("env should override file addr: got %q", got.WardenAddr)
	}
	if got.Token != "env-token" {
		t.Fatalf("env should override file token: got %q", got.Token)
	}
	if got.CAFile != "/file/ca" {
		t.Fatalf("unset env must not clobber file CAFile: got %q", got.CAFile)
	}

	// Flag overrides both env and file.
	got = file.Overlay(Config{WardenAddr: "http://flag-addr"})
	if got.WardenAddr != "http://flag-addr" {
		t.Fatalf("flag should override env+file addr: got %q", got.WardenAddr)
	}
	if got.Token != "env-token" {
		t.Fatalf("token should still come from env: got %q", got.Token)
	}
	if got.CAFile != "/file/ca" {
		t.Fatalf("CAFile should still come from file: got %q", got.CAFile)
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
