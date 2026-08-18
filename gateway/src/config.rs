//! Gateway runtime configuration from the environment.
use std::env;

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
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        fn req(k: &str) -> anyhow::Result<String> {
            env::var(k).map_err(|_| anyhow::anyhow!("missing required env {k}"))
        }
        fn opt(k: &str, d: &str) -> String {
            env::var(k).unwrap_or_else(|_| d.to_string())
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
        })
    }
}
