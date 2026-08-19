//! jumpgate ssh-proxy worker: the SSH data-plane worker behind the gateway.
//!
//! Thin process wrapper over the `ssh_proxy` library crate: install the crypto
//! provider, init tracing, load [`Config`], and run the data-plane mTLS server.

use ssh_proxy::config::Config;
use ssh_proxy::server::run_dataplane_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // rustls 0.23 requires a process-wide default crypto provider. We use the
    // `ring` provider (no C toolchain needed), matching the gateway.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))?;

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid ssh-proxy configuration");
            return Err(e);
        }
    };
    tracing::info!(
        worker_id = %config.worker_id,
        dataplane_addr = %config.dataplane_addr,
        warden_mesh_addr = %config.warden_mesh_addr,
        capacity = config.capacity,
        "ssh-proxy starting",
    );

    run_dataplane_server(&config).await
}
