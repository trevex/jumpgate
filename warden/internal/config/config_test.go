package config

import (
	"strings"
	"testing"
	"time"
)

// valid returns a Config with every duration field positive.
func valid() Config {
	return Config{
		ShutdownTimeout:     15 * time.Second,
		MaxGrantTTL:         8 * time.Hour,
		ReaperInterval:      30 * time.Second,
		AuditDrainInterval:  time.Second,
		AuditAnchorInterval: time.Hour,
		AuthzSweepInterval:  30 * time.Second,
		AuthzSweepDebounce:  200 * time.Millisecond,
		OrphanGCInterval:    30 * time.Second,
		OrphanGrace:         45 * time.Second,
		TeardownGrace:       30 * time.Second,
		SessionTokenTTL:     60 * time.Second,
		SSHCertMaxTTL:       8 * time.Hour,
		RecordingURLTTL:     5 * time.Minute,
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
}
