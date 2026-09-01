//! rdp-proxy worker runtime configuration from the environment.
//!
//! The same `WORKER_*` / `WARDEN_*` / `*_SPIFFE` vars ssh-proxy reads, minus the
//! recording-S3 and host-key-pin knobs (Phase 2 does not record and RDP pins the
//! target's server CA per-session via SetupSession, not a deploy-time toggle).
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    /// WORKER_ID — this worker's stable identity (mesh SPIFFE id + roster id).
    pub worker_id: String,
    /// WORKER_DATAPLANE_ADDR — the mTLS data-plane listener the gateway dials.
    pub dataplane_addr: String,
    /// WORKER_HEALTH_ADDR — a plaintext TCP listener for kubelet probes (the
    /// data-plane port is mesh mTLS and cannot be probed by a bare `tcpSocket`).
    pub health_addr: String,
    /// WORKER_MESH_CERT — this worker's mesh leaf cert PEM path.
    pub mesh_cert: String,
    /// WORKER_MESH_KEY — this worker's mesh leaf key PEM path.
    pub mesh_key: String,
    /// WORKER_MESH_CA — the mesh CA bundle PEM path.
    pub mesh_ca: String,
    /// WARDEN_MESH_ADDR — warden's mesh endpoint, dialed by the WorkerStream client.
    pub warden_mesh_addr: String,
    /// WORKER_CAPACITY — advertised session capacity.
    pub capacity: u32,
    /// GATEWAY_SPIFFE — the expected SPIFFE id of the gateway's mesh client cert,
    /// pinned by the data-plane mTLS verifier.
    pub gateway_spiffe: String,
    /// WARDEN_SPIFFE — the expected SPIFFE id of warden's mesh server cert,
    /// pinned by the WorkerStream control client.
    pub warden_spiffe: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        fn req(k: &str) -> anyhow::Result<String> {
            env::var(k).map_err(|_| anyhow::anyhow!("missing required env {k}"))
        }
        fn opt(k: &str, d: &str) -> String {
            env::var(k).unwrap_or_else(|_| d.to_string())
        }
        let capacity = match env::var("WORKER_CAPACITY") {
            Ok(v) => v
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("WORKER_CAPACITY must be a non-negative integer"))?,
            Err(_) => 100,
        };
        Ok(Self {
            worker_id: req("WORKER_ID")?,
            dataplane_addr: opt("WORKER_DATAPLANE_ADDR", "0.0.0.0:9000"),
            health_addr: opt("WORKER_HEALTH_ADDR", "0.0.0.0:9001"),
            mesh_cert: req("WORKER_MESH_CERT")?,
            mesh_key: req("WORKER_MESH_KEY")?,
            mesh_ca: req("WORKER_MESH_CA")?,
            warden_mesh_addr: req("WARDEN_MESH_ADDR")?,
            capacity,
            gateway_spiffe: opt("GATEWAY_SPIFFE", "spiffe://jumpgate/gateway/gateway"),
            warden_spiffe: opt("WARDEN_SPIFFE", "spiffe://jumpgate/warden/warden"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Required vars parse; optionals fall back to their documented defaults.
    #[test]
    fn from_env_defaults_and_required() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let keys = [
            "WORKER_ID",
            "WORKER_DATAPLANE_ADDR",
            "WORKER_HEALTH_ADDR",
            "WORKER_MESH_CERT",
            "WORKER_MESH_KEY",
            "WORKER_MESH_CA",
            "WARDEN_MESH_ADDR",
            "WORKER_CAPACITY",
            "GATEWAY_SPIFFE",
            "WARDEN_SPIFFE",
        ];
        for k in keys {
            env::remove_var(k);
        }

        // Missing required var → error.
        assert!(Config::from_env().is_err());

        env::set_var("WORKER_ID", "rdp-1");
        env::set_var("WORKER_MESH_CERT", "/c");
        env::set_var("WORKER_MESH_KEY", "/k");
        env::set_var("WORKER_MESH_CA", "/ca");
        env::set_var("WARDEN_MESH_ADDR", "https://warden:8444");

        let cfg = Config::from_env().expect("defaults parse");
        assert_eq!(cfg.worker_id, "rdp-1");
        assert_eq!(cfg.dataplane_addr, "0.0.0.0:9000");
        assert_eq!(cfg.health_addr, "0.0.0.0:9001");
        assert_eq!(cfg.capacity, 100);
        assert_eq!(cfg.gateway_spiffe, "spiffe://jumpgate/gateway/gateway");
        assert_eq!(cfg.warden_spiffe, "spiffe://jumpgate/warden/warden");

        for k in keys {
            env::remove_var(k);
        }
    }
}
