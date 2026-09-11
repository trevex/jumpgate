// Package config loads control-plane configuration from the environment.
package config

import (
	"fmt"
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
	// AuthSessionTTL is the absolute lifetime of a browser/CLI login token.
	AuthSessionTTL time.Duration `env:"AUTH_SESSION_TTL" envDefault:"12h"`
	// AuthSessionIdleTTL rejects a login token unused for longer than this.
	// Zero disables the idle check.
	AuthSessionIdleTTL time.Duration `env:"AUTH_SESSION_IDLE_TTL" envDefault:"2h"`
	// OIDC single sign-on. Empty OIDCIssuerURL disables OIDC entirely (local
	// accounts remain the break-glass path). When set, client id/secret/redirect
	// are required.
	OIDCIssuerURL    string `env:"OIDC_ISSUER_URL" envDefault:""`
	OIDCClientID     string `env:"OIDC_CLIENT_ID" envDefault:""`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET" envDefault:""`
	OIDCRedirectURL  string `env:"OIDC_REDIRECT_URL" envDefault:""`
	OIDCGroupsClaim  string `env:"OIDC_GROUPS_CLAIM" envDefault:"groups"`
	OIDCScopes       string `env:"OIDC_SCOPES" envDefault:"openid email profile groups"`

	// MaxRequestBytes caps the user-API request body. Auth/management payloads
	// are tiny; recording uploads go worker->S3, not through this API.
	MaxRequestBytes int64 `env:"MAX_REQUEST_BYTES" envDefault:"1048576"`
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

	// Probe execution bounds are sent to workers with credential-free assignments.
	// Lease duration bounds worker ownership; capacity prevents probes from
	// consuming an unbounded share of any worker.
	ProbeDNSTimeout       time.Duration `env:"PROBE_DNS_TIMEOUT" envDefault:"10s"`
	ProbeConnectTimeout   time.Duration `env:"PROBE_CONNECT_TIMEOUT" envDefault:"10s"`
	ProbeHandshakeTimeout time.Duration `env:"PROBE_HANDSHAKE_TIMEOUT" envDefault:"15s"`
	ProbeTotalTimeout     time.Duration `env:"PROBE_TOTAL_TIMEOUT" envDefault:"30s"`
	ProbeLeaseDuration    time.Duration `env:"PROBE_LEASE_DURATION" envDefault:"30s"`
	ProbeMaxAttempts      int           `env:"PROBE_MAX_ATTEMPTS" envDefault:"3"`
	ProbeMaxPerWorker     int           `env:"PROBE_MAX_PER_WORKER" envDefault:"2"`

	// Continuous target-identity monitoring. Periodic probing is DISABLED by
	// default: with PeriodicProbeEnabled=false the scheduler and notification
	// drainer are never started, so no periodic probe is queued and no operational
	// notification is produced until an operator opts in. Identity verification
	// itself is unaffected and stays mandatory — this flag only governs the
	// background re-probing cadence, not the enforcement gates.
	PeriodicProbeEnabled     bool          `env:"PERIODIC_PROBE_ENABLED" envDefault:"false"`
	PeriodicProbeInterval    time.Duration `env:"PERIODIC_PROBE_INTERVAL" envDefault:"5m"`
	PeriodicProbeJitter      time.Duration `env:"PERIODIC_PROBE_JITTER" envDefault:"1m"`
	PeriodicProbeConcurrency int           `env:"PERIODIC_PROBE_CONCURRENCY" envDefault:"32"`
	// NotificationDrainInterval is how often the notification outbox drainer
	// delivers enqueued events (mismatch, repeated failure, approaching expiry)
	// via the configured delivery adapter. Delivery is best-effort and retried;
	// it never changes authorization state.
	NotificationDrainInterval time.Duration `env:"NOTIFICATION_DRAIN_INTERVAL" envDefault:"5s"`

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
	// store warden reads recordings from (server-side cast streaming) and anchors the
	// audit chain into. An empty bucket disables recording retrieval (RecordingService
	// mounts but download fails closed). RecordingS3Endpoint must be reachable FROM
	// warden (in-cluster service DNS in Kubernetes), not a client-only NodePort/ingress.
	//
	// RecordingS3PublicEndpoint is the host baked into presigned download URLs handed
	// to an off-cluster client (an auditor's CLI). Presigning is offline, so it need
	// not be reachable from warden. Empty falls back to RecordingS3Endpoint.
	RecordingBucket           string        `env:"RECORDING_BUCKET"`
	RecordingS3Endpoint       string        `env:"RECORDING_S3_ENDPOINT"`
	RecordingS3PublicEndpoint string        `env:"RECORDING_S3_PUBLIC_ENDPOINT"`
	RecordingS3Region         string        `env:"RECORDING_S3_REGION" envDefault:"us-east-1"`
	RecordingURLTTL           time.Duration `env:"RECORDING_URL_TTL" envDefault:"5m"`

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

// OIDCEnabled reports whether OIDC login is configured.
func (c Config) OIDCEnabled() bool { return c.OIDCIssuerURL != "" }

// Load reads configuration from environment variables and validates it.
func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate rejects meaningless configuration that env.Parse accepts structurally.
// The background loops and TTL clamps all assume strictly-positive durations; a
// zero or negative (e.g. REAPER_INTERVAL=0s) would busy-loop or disable a bound
// silently, so fail fast at boot instead. env.Parse already enforces `required`
// presence and type, so this only checks meaning.
func (c Config) Validate() error {
	for _, d := range []struct {
		name string
		val  time.Duration
	}{
		{"SHUTDOWN_TIMEOUT", c.ShutdownTimeout},
		{"MAX_GRANT_TTL", c.MaxGrantTTL},
		{"REAPER_INTERVAL", c.ReaperInterval},
		{"AUDIT_DRAIN_INTERVAL", c.AuditDrainInterval},
		{"AUDIT_ANCHOR_INTERVAL", c.AuditAnchorInterval},
		{"AUTHZ_SWEEP_INTERVAL", c.AuthzSweepInterval},
		{"AUTHZ_SWEEP_DEBOUNCE", c.AuthzSweepDebounce},
		{"ORPHAN_GC_INTERVAL", c.OrphanGCInterval},
		{"ORPHAN_GRACE", c.OrphanGrace},
		{"TEARDOWN_GRACE", c.TeardownGrace},
		{"SESSION_TOKEN_TTL", c.SessionTokenTTL},
		{"AUTH_SESSION_TTL", c.AuthSessionTTL},
		{"SSH_CERT_MAX_TTL", c.SSHCertMaxTTL},
		{"RECORDING_URL_TTL", c.RecordingURLTTL},
		{"PROBE_DNS_TIMEOUT", c.ProbeDNSTimeout},
		{"PROBE_CONNECT_TIMEOUT", c.ProbeConnectTimeout},
		{"PROBE_HANDSHAKE_TIMEOUT", c.ProbeHandshakeTimeout},
		{"PROBE_TOTAL_TIMEOUT", c.ProbeTotalTimeout},
		{"PROBE_LEASE_DURATION", c.ProbeLeaseDuration},
		{"PERIODIC_PROBE_INTERVAL", c.PeriodicProbeInterval},
		{"NOTIFICATION_DRAIN_INTERVAL", c.NotificationDrainInterval},
	} {
		if d.val <= 0 {
			return fmt.Errorf("%s must be a positive duration, got %s", d.name, d.val)
		}
	}
	if c.PeriodicProbeJitter < 0 {
		return fmt.Errorf("PERIODIC_PROBE_JITTER must not be negative, got %s", c.PeriodicProbeJitter)
	}
	if c.PeriodicProbeConcurrency < 1 {
		return fmt.Errorf("PERIODIC_PROBE_CONCURRENCY must be positive, got %d", c.PeriodicProbeConcurrency)
	}
	if c.ProbeTotalTimeout < c.ProbeDNSTimeout || c.ProbeTotalTimeout < c.ProbeConnectTimeout || c.ProbeTotalTimeout < c.ProbeHandshakeTimeout {
		return fmt.Errorf("PROBE_TOTAL_TIMEOUT must not be shorter than any probe stage")
	}
	if c.ProbeMaxAttempts < 1 || c.ProbeMaxAttempts > 10 {
		return fmt.Errorf("PROBE_MAX_ATTEMPTS must be between 1 and 10, got %d", c.ProbeMaxAttempts)
	}
	if c.ProbeMaxPerWorker < 1 {
		return fmt.Errorf("PROBE_MAX_PER_WORKER must be positive, got %d", c.ProbeMaxPerWorker)
	}
	if c.MaxRequestBytes <= 0 {
		return fmt.Errorf("MAX_REQUEST_BYTES must be positive, got %d", c.MaxRequestBytes)
	}
	if c.AuthSessionIdleTTL < 0 {
		return fmt.Errorf("AUTH_SESSION_IDLE_TTL must not be negative, got %s", c.AuthSessionIdleTTL)
	}
	if c.OIDCEnabled() {
		if c.OIDCClientID == "" || c.OIDCClientSecret == "" || c.OIDCRedirectURL == "" {
			return fmt.Errorf("OIDC_ISSUER_URL is set but OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URL are required")
		}
	}
	return nil
}
