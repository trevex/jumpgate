package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/jumpgate")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DatabaseURL != "postgres://localhost/jumpgate" {
		t.Fatalf("DatabaseURL = %q", c.DatabaseURL)
	}
	if c.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr default = %q, want :8080", c.ListenAddr)
	}
	if c.ShutdownTimeout != 15*time.Second {
		t.Fatalf("ShutdownTimeout default = %v, want 15s", c.ShutdownTimeout)
	}
	if c.LogLevel != "info" {
		t.Fatalf("LogLevel default = %q, want \"info\"", c.LogLevel)
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://placeholder")  // registers auto-restore on cleanup
	if err := os.Unsetenv("DATABASE_URL"); err != nil { // fully absent for the Load() call
		t.Fatalf("Unsetenv: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error when DATABASE_URL is unset, got nil")
	}
}
