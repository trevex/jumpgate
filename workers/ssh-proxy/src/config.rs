//! ssh-proxy worker runtime configuration from the environment.
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    /// WORKER_ID — this worker's stable identity (used for its mesh SPIFFE id
    /// and roster registration).
    pub worker_id: String,
    /// WORKER_DATAPLANE_ADDR — the mTLS data-plane listener the gateway dials.
    pub dataplane_addr: String,
    /// WORKER_HEALTH_ADDR — a plaintext TCP listener for kubelet liveness/
    /// readiness probes. The data-plane port is mesh mTLS and cannot be probed by
    /// a bare TCP/`tcpSocket` probe (the handshake fails), so probes target this.
    pub health_addr: String,
    /// WORKER_MESH_CERT — this worker's mesh leaf cert PEM path.
    pub mesh_cert: String,
    /// WORKER_MESH_KEY — this worker's mesh leaf key PEM path.
    pub mesh_key: String,
    /// WORKER_MESH_CA — the mesh CA bundle PEM path.
    pub mesh_ca: String,
    /// WARDEN_MESH_ADDR — warden's mesh endpoint (e.g. https://warden:8444),
    /// dialed by the WorkerStream control client.
    pub warden_mesh_addr: String,
    /// WORKER_CAPACITY — advertised session capacity.
    pub capacity: u32,
    /// GATEWAY_SPIFFE — the expected SPIFFE id of the gateway's mesh client
    /// cert, pinned by the data-plane mTLS verifier.
    pub gateway_spiffe: String,
    /// WARDEN_SPIFFE — the expected SPIFFE id of warden's mesh server cert,
    /// pinned by the WorkerStream control client.
    pub warden_spiffe: String,
    /// RECORDING_BUCKET — S3 bucket session recordings are uploaded to.
    pub recording_bucket: String,
    /// RECORDING_S3_ENDPOINT — custom S3 endpoint (e.g. MinIO); empty = AWS default.
    pub recording_s3_endpoint: String,
    /// RECORDING_S3_REGION — S3 region for recording uploads.
    pub recording_s3_region: String,
    /// RECORDING_PART_SIZE — multipart upload part size in bytes.
    pub recording_part_size: usize,
    /// WORKER_REQUIRE_HOST_KEY_PIN — when true, a target with no configured
    /// host-key pin is rejected (fail closed) instead of accept-and-logged.
    /// Default false preserves accept-and-log for unpinned assets.
    pub require_host_key_pin: bool,
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
        let recording_part_size = match env::var("RECORDING_PART_SIZE") {
            Ok(v) => v.parse::<usize>().map_err(|_| {
                anyhow::anyhow!("RECORDING_PART_SIZE must be a non-negative integer")
            })?,
            Err(_) => crate::record::MIN_PART_SIZE,
        };
        // S3 rejects a non-final multipart part below 5 MiB, so a smaller part size
        // can never trigger an early upload — it would silently do nothing. Clamp
        // up to the floor and tell the operator rather than accept a dead value.
        let recording_part_size = if recording_part_size < crate::record::MIN_PART_SIZE {
            tracing::warn!(
                requested = recording_part_size,
                floor = crate::record::MIN_PART_SIZE,
                "RECORDING_PART_SIZE is below S3's 5 MiB minimum; clamping up to the floor",
            );
            crate::record::MIN_PART_SIZE
        } else {
            recording_part_size
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
            recording_bucket: opt("RECORDING_BUCKET", ""),
            recording_s3_endpoint: opt("RECORDING_S3_ENDPOINT", ""),
            recording_s3_region: opt("RECORDING_S3_REGION", "us-east-1"),
            recording_part_size,
            require_host_key_pin: matches!(
                opt("WORKER_REQUIRE_HOST_KEY_PIN", "false").trim(),
                "true" | "1"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recording knobs fall back to their documented defaults when unset,
    /// and `from_env` parses the numeric ones when present.
    ///
    /// Env is process-global; this test owns the recording vars plus the
    /// required vars and clears them again to avoid bleeding into siblings.
    #[test]
    fn recording_config_defaults_and_parsing() {
        // Serialize with any other env-touching test in this binary.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let keys = [
            "WORKER_ID",
            "WORKER_MESH_CERT",
            "WORKER_MESH_KEY",
            "WORKER_MESH_CA",
            "WARDEN_MESH_ADDR",
            "RECORDING_BUCKET",
            "RECORDING_S3_ENDPOINT",
            "RECORDING_S3_REGION",
            "RECORDING_PART_SIZE",
        ];
        for k in keys {
            env::remove_var(k);
        }

        // Required vars so from_env reaches the recording fields.
        env::set_var("WORKER_ID", "w1");
        env::set_var("WORKER_MESH_CERT", "/c");
        env::set_var("WORKER_MESH_KEY", "/k");
        env::set_var("WORKER_MESH_CA", "/ca");
        env::set_var("WARDEN_MESH_ADDR", "https://warden:8444");

        // Recording vars unset → defaults.
        let cfg = Config::from_env().expect("defaults parse");
        assert_eq!(cfg.recording_bucket, "");
        assert_eq!(cfg.recording_s3_endpoint, "");
        assert_eq!(cfg.recording_s3_region, "us-east-1");
        assert_eq!(cfg.recording_part_size, 5 * 1024 * 1024);

        // Recording vars set → parsed.
        env::set_var("RECORDING_BUCKET", "recordings");
        env::set_var("RECORDING_S3_ENDPOINT", "http://minio:9000");
        env::set_var("RECORDING_S3_REGION", "eu-central-1");
        env::set_var("RECORDING_PART_SIZE", "8388608");

        let cfg = Config::from_env().expect("set values parse");
        assert_eq!(cfg.recording_bucket, "recordings");
        assert_eq!(cfg.recording_s3_endpoint, "http://minio:9000");
        assert_eq!(cfg.recording_s3_region, "eu-central-1");
        assert_eq!(cfg.recording_part_size, 8 * 1024 * 1024);

        for k in keys {
            env::remove_var(k);
        }
    }
}
