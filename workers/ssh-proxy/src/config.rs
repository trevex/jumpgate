//! ssh-proxy worker runtime configuration from the environment.
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    /// WORKER_ID — this worker's stable identity (used for its mesh SPIFFE id
    /// and roster registration).
    pub worker_id: String,
    /// WORKER_DATAPLANE_ADDR — the mTLS data-plane listener the gateway dials.
    pub dataplane_addr: String,
    /// WORKER_MESH_CERT — this worker's mesh leaf cert PEM path.
    pub mesh_cert: String,
    /// WORKER_MESH_KEY — this worker's mesh leaf key PEM path.
    pub mesh_key: String,
    /// WORKER_MESH_CA — the mesh CA bundle PEM path.
    pub mesh_ca: String,
    /// WARDEN_MESH_ADDR — warden's mesh endpoint (e.g. https://warden:8444),
    /// dialed by the WorkerStream control client (Task 6).
    pub warden_mesh_addr: String,
    /// WORKER_CAPACITY — advertised session capacity.
    pub capacity: u32,
    /// GATEWAY_SPIFFE — the expected SPIFFE id of the gateway's mesh client
    /// cert, pinned by the data-plane mTLS verifier.
    pub gateway_spiffe: String,
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
            mesh_cert: req("WORKER_MESH_CERT")?,
            mesh_key: req("WORKER_MESH_KEY")?,
            mesh_ca: req("WORKER_MESH_CA")?,
            warden_mesh_addr: req("WARDEN_MESH_ADDR")?,
            capacity,
            gateway_spiffe: opt("GATEWAY_SPIFFE", "spiffe://jumpgate/gateway/gateway"),
        })
    }
}
