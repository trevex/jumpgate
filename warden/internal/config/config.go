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

	// AuditAnchorInterval is how often the anchorer externalizes the audit hash-chain
	// tip (max seq + its entry_hash) to the object store under a distinct append-only
	// key, so tail truncation of the in-DB chain becomes detectable by cross-checking
	// against the last anchor. Best-effort defense-in-depth: it only runs when an
	// object store is configured (RECORDING_BUCKET), and any error is logged, never
	// blocking. It skips writing when the tip has not advanced since the last anchor.
	AuditAnchorInterval time.Duration `env:"AUDIT_ANCHOR_INTERVAL" envDefault:"1h"`

	// VaultMasterKey is the base64-encoded 32-byte master KEK that seals CA private
	// keys and stored secrets at rest. Empty means the vault is disabled.
	VaultMasterKey string `env:"VAULT_MASTER_KEY"`

	// AuthzSweepInterval is the pull-sweep backstop period: how often each replica
	// re-evaluates its owned live sessions even without a change notification.
	AuthzSweepInterval time.Duration `env:"AUTHZ_SWEEP_INTERVAL" envDefault:"30s"`
	// AuthzSweepDebounce coalesces a burst of authorization-change notifications into
	// a single sweep.
	AuthzSweepDebounce time.Duration `env:"AUTHZ_SWEEP_DEBOUNCE" envDefault:"200ms"`
	// OrphanGCInterval is how often the live-session ledger is reconciled against
	// worker presence.
	OrphanGCInterval time.Duration `env:"ORPHAN_GC_INTERVAL" envDefault:"30s"`
	// OrphanGrace is how long a worker may miss heartbeats before its live sessions
	// are reaped as unreachable (a small multiple of the heartbeat interval).
	OrphanGrace time.Duration `env:"ORPHAN_GRACE" envDefault:"45s"`
	// TeardownGrace is how long a session may stay marked-terminating (its teardown
	// unconfirmed) before it is force-cleaned from the ledger.
	TeardownGrace time.Duration `env:"TEARDOWN_GRACE" envDefault:"30s"`

	// SessionTokenTTL bounds the data-plane admission token lifetime (an admission
	// ticket; the session outlives it — teardown handles in-session revocation).
	SessionTokenTTL time.Duration `env:"SESSION_TOKEN_TTL" envDefault:"60s"`
	// GatewayEndpoint is the externally reachable gateway address the CLI dials.
	GatewayEndpoint string `env:"GATEWAY_ENDPOINT" envDefault:"localhost:8443"`
	// AllowInsecureSessions (DEV ONLY) permits CreateWebSession to hand back the
	// plaintext gateway endpoint when the browser asks for it. Default false: an
	// insecure request is silently downgraded to the secure endpoint (fail-closed).
	AllowInsecureSessions bool `env:"ALLOW_INSECURE_SESSIONS" envDefault:"false"`
	// GatewayInsecureEndpoint is the plaintext (ws://) gateway address handed to a
	// browser when insecure sessions are allowed and requested. Empty disables the
	// insecure path regardless of AllowInsecureSessions (fail-closed).
	GatewayInsecureEndpoint string `env:"GATEWAY_INSECURE_ENDPOINT" envDefault:""`

	// SSHCertMaxTTL bounds an issued JIT SSH certificate's lifetime. It is a
	// backstop only: teardown handles in-session revocation, so the cert TTL need
	// not be short — it just caps a session that outlives all warden signals.
	SSHCertMaxTTL time.Duration `env:"SSH_CERT_MAX_TTL" envDefault:"8h"`

	// MeshListenAddr is the address of warden's second, mTLS "mesh" listener that
	// serves the worker/gateway-facing services (Dataplane + Gateway). Empty means
	// the mesh listener is disabled (workers/gateway cannot connect — a degraded but
	// acceptable boot mode; the user-facing bearer API still serves).
	MeshListenAddr string `env:"MESH_LISTEN_ADDR"`
	// MeshCertFile / MeshKeyFile / MeshCAFile are the PEM files for warden's mesh
	// server leaf keypair and the mesh CA bundle it verifies worker/gateway client
	// certs against. All three must load for the mesh listener to start.
	MeshCertFile string `env:"MESH_CERT_FILE"`
	MeshKeyFile  string `env:"MESH_KEY_FILE"`
	MeshCAFile   string `env:"MESH_CA_FILE"`

	// RecordingBucket / RecordingS3Endpoint / RecordingS3Region configure the object
	// store warden presigns recording download URLs against. An empty bucket disables
	// recording retrieval (RecordingService mounts but download fails closed).
	RecordingBucket     string        `env:"RECORDING_BUCKET"`
	RecordingS3Endpoint string        `env:"RECORDING_S3_ENDPOINT"`
	RecordingS3Region   string        `env:"RECORDING_S3_REGION" envDefault:"us-east-1"`
	RecordingURLTTL     time.Duration `env:"RECORDING_URL_TTL" envDefault:"5m"`

	// CookieInsecure controls whether Set-Cookie omits the Secure flag. The
	// logical accessor is CookieSecure() (returns !CookieInsecure, default true);
	// set JUMPGATE_COOKIE_INSECURE=true in dev environments where warden is accessed
	// over plain HTTP so the browser accepts the session cookie.
	CookieInsecure bool `env:"JUMPGATE_COOKIE_INSECURE"`

	// DevCORSOrigins is a comma-separated allowlist of origins (e.g.
	// "http://localhost:5173,http://localhost:3000") whose browser requests receive
	// CORS headers. Empty (the default) disables CORS — production serves the SPA
	// same-origin and needs no CORS.
	DevCORSOrigins []string `env:"JUMPGATE_DEV_CORS_ORIGINS"`
}

// CookieSecure returns true unless JUMPGATE_COOKIE_INSECURE is set, expressing
// the intent that secure cookies are on by default and insecure is the opt-out.
func (c Config) CookieSecure() bool { return !c.CookieInsecure }

// Load reads configuration from environment variables.
func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}
