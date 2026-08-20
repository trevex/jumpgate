package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trevex/jumpgate/cli/internal/config"
)

// seedConfig writes a config file with two contexts into a temp XDG dir.
func seedConfig(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := config.File{
		CurrentContext: "prod",
		Contexts: map[string]config.Context{
			"prod": {WardenAddr: "https://prod:8080", Token: "p-tok"},
			"dev":  {WardenAddr: "http://dev:8080", Token: "d-tok"},
		},
	}
	if err := f.Save(); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestConfigUseContextKnown(t *testing.T) {
	seedConfig(t)
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"config", "use-context", "dev"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !strings.Contains(out.String(), `switched to context "dev"`) {
		t.Fatalf("out=%s", out.String())
	}
	f, _ := config.LoadFile()
	if f.CurrentContext != "dev" {
		t.Fatalf("current=%q", f.CurrentContext)
	}
}

func TestConfigUseContextUnknown(t *testing.T) {
	seedConfig(t)
	t.Cleanup(func() { flagOutput = "table" })

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"config", "use-context", "nope"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected unknown-context error, got %v", err)
	}
}

func TestConfigGetContexts(t *testing.T) {
	seedConfig(t)
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"config", "get-contexts"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "CURRENT") || !strings.Contains(got, "prod") || !strings.Contains(got, "dev") {
		t.Fatalf("out=%s", got)
	}
	// The current context (prod) must carry the marker; dev must not.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "prod") && !strings.Contains(line, "*") {
			t.Fatalf("prod missing current marker: %q", line)
		}
		if strings.Contains(line, "dev") && strings.Contains(line, "*") {
			t.Fatalf("dev should not carry marker: %q", line)
		}
	}
}

func TestConfigCurrentContext(t *testing.T) {
	seedConfig(t)
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"config", "current-context"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.TrimSpace(out.String()) != "prod" {
		t.Fatalf("out=%q", out.String())
	}
}

func TestConfigGetContextsJSON(t *testing.T) {
	seedConfig(t)
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"config", "get-contexts", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, `"warden_addr"`) || !strings.Contains(got, `"current"`) || !strings.Contains(got, "prod") {
		t.Fatalf("out=%s", got)
	}
}
