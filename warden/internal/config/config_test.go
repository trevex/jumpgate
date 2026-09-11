package config

import (
	"strings"
	"testing"
	"time"
)

// valid returns a Config with every duration field positive.
func valid() Config {
	return Config{
		ShutdownTimeout:       15 * time.Second,
		MaxGrantTTL:           8 * time.Hour,
		ReaperInterval:        30 * time.Second,
		AuditDrainInterval:    time.Second,
		AuditAnchorInterval:   time.Hour,
		AuthzSweepInterval:    30 * time.Second,
		AuthzSweepDebounce:    200 * time.Millisecond,
		OrphanGCInterval:      30 * time.Second,
		OrphanGrace:           45 * time.Second,
		TeardownGrace:         30 * time.Second,
		SessionTokenTTL:       60 * time.Second,
		AuthSessionTTL:        12 * time.Hour,
		MaxRequestBytes:       1048576,
		SSHCertMaxTTL:         8 * time.Hour,
		RecordingURLTTL:       5 * time.Minute,
		ProbeDNSTimeout:       10 * time.Second,
		ProbeConnectTimeout:   10 * time.Second,
		ProbeHandshakeTimeout: 15 * time.Second,
		ProbeTotalTimeout:     30 * time.Second,
		ProbeLeaseDuration:    30 * time.Second,
		ProbeMaxAttempts:      3,
		ProbeMaxPerWorker:     2,

		PeriodicProbeInterval:     5 * time.Minute,
		PeriodicProbeJitter:       time.Minute,
		PeriodicProbeConcurrency:  32,
		NotificationDrainInterval: 5 * time.Second,
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	c := valid()
	c.ReaperInterval = 0
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "REAPER_INTERVAL") {
		t.Fatalf("zero ReaperInterval: got %v, want an error naming REAPER_INTERVAL", err)
	}

	c = valid()
	c.SSHCertMaxTTL = -time.Second
	if err := c.Validate(); err == nil {
		t.Fatal("negative SSHCertMaxTTL accepted")
	}

	c = valid()
	c.ProbeTotalTimeout = c.ProbeHandshakeTimeout - time.Second
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "PROBE_TOTAL_TIMEOUT") {
		t.Fatalf("short probe total timeout = %v, want named error", err)
	}

	c = valid()
	c.ProbeMaxPerWorker = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "PROBE_MAX_PER_WORKER") {
		t.Fatalf("zero probe worker capacity = %v, want named error", err)
	}

	c = valid()
	c.PeriodicProbeConcurrency = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "PERIODIC_PROBE_CONCURRENCY") {
		t.Fatalf("zero periodic concurrency = %v, want named error", err)
	}

	// Zero jitter is legitimate (no spread); it must be accepted.
	c = valid()
	c.PeriodicProbeJitter = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("zero jitter rejected: %v", err)
	}

	c = valid()
	c.AuthSessionTTL = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_SESSION_TTL") {
		t.Fatalf("zero AuthSessionTTL = %v, want named error", err)
	}

	// Zero idle TTL means the idle check is disabled; it must be accepted.
	c = valid()
	c.AuthSessionIdleTTL = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("zero AuthSessionIdleTTL rejected: %v", err)
	}

	c = valid()
	c.AuthSessionIdleTTL = -time.Second
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_SESSION_IDLE_TTL") {
		t.Fatalf("negative AuthSessionIdleTTL = %v, want named error", err)
	}

	c = valid()
	c.MaxRequestBytes = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "MAX_REQUEST_BYTES") {
		t.Fatalf("zero MaxRequestBytes = %v, want named error", err)
	}

	// OIDC disabled (empty issuer, the default) must be accepted.
	c = valid()
	if err := c.Validate(); err != nil {
		t.Fatalf("OIDC disabled rejected: %v", err)
	}
	if c.OIDCEnabled() {
		t.Fatal("OIDCEnabled true with empty OIDCIssuerURL")
	}

	// OIDC enabled but missing required fields must be rejected.
	c = valid()
	c.OIDCIssuerURL = "https://idp.example.com"
	c.OIDCClientID = "client-id"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "OIDC") {
		t.Fatalf("OIDC enabled with missing client secret/redirect = %v, want named error", err)
	}

	// OIDC fully configured must be accepted.
	c = valid()
	c.OIDCIssuerURL = "https://idp.example.com"
	c.OIDCClientID = "client-id"
	c.OIDCClientSecret = "client-secret"
	c.OIDCRedirectURL = "https://warden.example.com/oidc/callback"
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured OIDC rejected: %v", err)
	}
	if !c.OIDCEnabled() {
		t.Fatal("OIDCEnabled false with OIDCIssuerURL set")
	}
}

func TestProbeDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProbeDNSTimeout != 10*time.Second || cfg.ProbeConnectTimeout != 10*time.Second || cfg.ProbeHandshakeTimeout != 15*time.Second || cfg.ProbeTotalTimeout != 30*time.Second || cfg.ProbeLeaseDuration != 30*time.Second || cfg.ProbeMaxAttempts != 3 || cfg.ProbeMaxPerWorker != 2 {
		t.Fatalf("probe defaults = %#v", cfg)
	}
}

func TestPeriodicProbeDisabledByDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeriodicProbeEnabled {
		t.Fatal("periodic probing must be disabled by default")
	}
	if cfg.PeriodicProbeInterval != 5*time.Minute || cfg.PeriodicProbeJitter != time.Minute || cfg.PeriodicProbeConcurrency != 32 || cfg.NotificationDrainInterval != 5*time.Second {
		t.Fatalf("periodic defaults = %#v", cfg)
	}
}
