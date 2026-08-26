//! Gateway runtime configuration from the environment.
use std::env;
use std::time::Duration;

/// Default cap on concurrent external connections (and per-connection tasks).
const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// Default idle timeout for a proxied session (no bytes/frames either way).
const DEFAULT_SESSION_IDLE_SECS: u64 = 900; // 15 min
/// Default absolute session lifetime cap (0 = unlimited).
const DEFAULT_SESSION_MAX_LIFETIME_SECS: u64 = 43_200; // 12 h

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,        // GATEWAY_LISTEN (external TLS), default 0.0.0.0:8443
    pub health_listen: String, // GATEWAY_HEALTH_LISTEN, default 0.0.0.0:8080
    pub tls_cert: String,      // GATEWAY_TLS_CERT (external server cert PEM path)
    pub tls_key: String,       // GATEWAY_TLS_KEY
    pub mesh_cert: String,     // GATEWAY_MESH_CERT (mesh client cert PEM path)
    pub mesh_key: String,      // GATEWAY_MESH_KEY
    pub mesh_ca: String,       // GATEWAY_MESH_CA (mesh CA bundle PEM path)
    pub warden_mesh_addr: String, // WARDEN_MESH_ADDR (e.g. https://warden:8444)
    pub warden_spiffe: String, // expected SPIFFE id of warden's mesh cert

    // --- resource bounds (DoS surface) ---------------------------------------
    /// GATEWAY_MAX_CONNECTIONS: cap on concurrent external connections (and the
    /// per-connection tasks they spawn). Default 4096.
    pub max_connections: usize,
    /// GATEWAY_SESSION_IDLE_TIMEOUT_SECS: tear a proxied session down if NO data
    /// flows in either direction for this long. Default 900s (15 min); 0 = off.
    pub session_idle_timeout: Duration,
    /// GATEWAY_SESSION_MAX_LIFETIME_SECS: absolute cap on a proxied session's
    /// wall-clock lifetime. Default 43200s (12 h); 0 = unlimited.
    pub session_max_lifetime: Duration,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        fn req(k: &str) -> anyhow::Result<String> {
            env::var(k).map_err(|_| anyhow::anyhow!("missing required env {k}"))
        }
        fn opt(k: &str, d: &str) -> String {
            env::var(k).unwrap_or_else(|_| d.to_string())
        }
        /// Parse a `usize` env var, falling back to `d` when unset; a present but
        /// unparseable value is a hard error (fail fast on misconfiguration).
        fn opt_usize(k: &str, d: usize) -> anyhow::Result<usize> {
            match env::var(k) {
                Ok(v) => v.parse().map_err(|_| {
                    anyhow::anyhow!("env {k} must be a non-negative integer, got {v:?}")
                }),
                Err(_) => Ok(d),
            }
        }
        /// Parse a seconds-valued `Duration` env var, falling back to `d` seconds
        /// when unset; `0` is a valid value (meaning "off"/"unlimited").
        fn opt_secs(k: &str, d: u64) -> anyhow::Result<Duration> {
            match env::var(k) {
                Ok(v) => v.parse::<u64>().map(Duration::from_secs).map_err(|_| {
                    anyhow::anyhow!("env {k} must be a non-negative integer of seconds, got {v:?}")
                }),
                Err(_) => Ok(Duration::from_secs(d)),
            }
        }

        let max_connections = opt_usize("GATEWAY_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)?;
        if max_connections == 0 {
            anyhow::bail!("GATEWAY_MAX_CONNECTIONS must be > 0");
        }
        Ok(Self {
            listen: opt("GATEWAY_LISTEN", "0.0.0.0:8443"),
            health_listen: opt("GATEWAY_HEALTH_LISTEN", "0.0.0.0:8080"),
            tls_cert: req("GATEWAY_TLS_CERT")?,
            tls_key: req("GATEWAY_TLS_KEY")?,
            mesh_cert: req("GATEWAY_MESH_CERT")?,
            mesh_key: req("GATEWAY_MESH_KEY")?,
            mesh_ca: req("GATEWAY_MESH_CA")?,
            warden_mesh_addr: req("WARDEN_MESH_ADDR")?,
            warden_spiffe: opt("WARDEN_MESH_SPIFFE", "spiffe://jumpgate/warden/warden"),
            max_connections,
            session_idle_timeout: opt_secs(
                "GATEWAY_SESSION_IDLE_TIMEOUT_SECS",
                DEFAULT_SESSION_IDLE_SECS,
            )?,
            session_max_lifetime: opt_secs(
                "GATEWAY_SESSION_MAX_LIFETIME_SECS",
                DEFAULT_SESSION_MAX_LIFETIME_SECS,
            )?,
        })
    }
}
