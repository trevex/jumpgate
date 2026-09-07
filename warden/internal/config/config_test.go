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
		SSHCertMaxTTL:         8 * time.Hour,
		RecordingURLTTL:       5 * time.Minute,
		ProbeDNSTimeout:       10 * time.Second,
		ProbeConnectTimeout:   10 * time.Second,
		ProbeHandshakeTimeout: 15 * time.Second,
		ProbeTotalTimeout:     30 * time.Second,
		ProbeLeaseDuration:    30 * time.Second,
		ProbeMaxAttempts:      3,
		ProbeMaxPerWorker:     2,
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
