// Package config loads control-plane configuration from the environment.
package config

import (
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the control-plane runtime configuration.
type Config struct {
	DatabaseURL     string        `env:"DATABASE_URL,required"`
	ListenAddr      string        `env:"LISTEN_ADDR" envDefault:":8080"`
	LogLevel        string        `env:"LOG_LEVEL" envDefault:"info"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	BootstrapAdminEmail    string `env:"BOOTSTRAP_ADMIN_EMAIL"`
	BootstrapAdminPassword string `env:"BOOTSTRAP_ADMIN_PASSWORD"`

	// MaxGrantTTL is the hard ceiling on a JIT access grant's lifetime. It clamps
	// both the requested duration and any per-policy max_duration cap.
	MaxGrantTTL time.Duration `env:"MAX_GRANT_TTL" envDefault:"8h"`

	// ReaperInterval is how often the expiry reaper sweeps for grants whose window
	// has elapsed, marking them revoked ('expired'), auditing, and tearing down any
	// live sessions. Authorization already excludes expired grants; the reaper only
	// drives the side effects (audit + teardown).
	ReaperInterval time.Duration `env:"REAPER_INTERVAL" envDefault:"30s"`

	// AuditDrainInterval is how often the transactional audit outbox drainer moves
	// enqueued events (written durably inside domain transactions) into the
	// hash-chained audit_log. A short interval keeps the chain close to real time.
	AuditDrainInterval time.Duration `env:"AUDIT_DRAIN_INTERVAL" envDefault:"1s"`

	// VaultMasterKey is the base64-encoded 32-byte master KEK that seals CA private
	// keys and stored secrets at rest. Empty means the vault is disabled.
	VaultMasterKey string `env:"VAULT_MASTER_KEY"`

	// SessionTokenTTL bounds the data-plane admission token lifetime (an admission
	// ticket; the session outlives it — teardown handles in-session revocation).
	SessionTokenTTL time.Duration `env:"SESSION_TOKEN_TTL" envDefault:"60s"`
	// GatewayEndpoint is the externally reachable gateway address the CLI dials.
	GatewayEndpoint string `env:"GATEWAY_ENDPOINT" envDefault:"localhost:8443"`

	// SSHCertMaxTTL bounds an issued JIT SSH certificate's lifetime. It is a
	// backstop only: teardown handles in-session revocation, so the cert TTL need
	// not be short — it just caps a session that outlives all warden signals.
	SSHCertMaxTTL time.Duration `env:"SSH_CERT_MAX_TTL" envDefault:"8h"`
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}
