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
	// CookieSecure must default to true (JUMPGATE_COOKIE_INSECURE unset).
	if !c.CookieSecure() {
		t.Fatal("CookieSecure() should default true when JUMPGATE_COOKIE_INSECURE is unset")
	}
	// DevCORSOrigins must be nil when JUMPGATE_DEV_CORS_ORIGINS is unset.
	if c.DevCORSOrigins != nil {
		t.Fatalf("DevCORSOrigins default = %v, want nil", c.DevCORSOrigins)
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

func TestCookieSecureInsecureOverride(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/jumpgate")
	t.Setenv("JUMPGATE_COOKIE_INSECURE", "true")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CookieSecure() {
		t.Fatal("CookieSecure() should be false when JUMPGATE_COOKIE_INSECURE=true")
	}
}

func TestDevCORSOriginsParsesList(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/jumpgate")
	t.Setenv("JUMPGATE_DEV_CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.DevCORSOrigins) != 2 {
		t.Fatalf("DevCORSOrigins = %v, want 2 entries", c.DevCORSOrigins)
	}
	if c.DevCORSOrigins[0] != "http://localhost:5173" {
		t.Fatalf("DevCORSOrigins[0] = %q, want http://localhost:5173", c.DevCORSOrigins[0])
	}
	if c.DevCORSOrigins[1] != "http://localhost:3000" {
		t.Fatalf("DevCORSOrigins[1] = %q, want http://localhost:3000", c.DevCORSOrigins[1])
	}
}
