//! jumpgate ssh-proxy worker: the SSH data-plane worker behind the gateway.
//!
//! Thin process wrapper over the `ssh_proxy` library crate: install the crypto
//! provider, init tracing, load [`Config`], and run the data-plane mTLS server.

use ssh_proxy::config::Config;
use ssh_proxy::control::{run_control, SessionRegistry};
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

    // Control-plane seam shared between the WorkerStream client and the data
    // plane: the registry lets `Teardown` force-close live sessions; the channel
    // carries `SessionEnded` reports from finished sessions to warden.
    let registry = SessionRegistry::default();
    let (session_ended_tx, session_ended_rx) = tokio::sync::mpsc::unbounded_channel();

    // The WorkerStream control loop runs alongside the data-plane server: it
    // registers this worker with warden, heartbeats, forwards SessionEnded, and
    // dispatches Teardown into `registry`. It reconnects on its own.
    tokio::spawn(run_control(
        config.clone(),
        registry.clone(),
        session_ended_rx,
    ));

    run_dataplane_server(&config, registry, session_ended_tx).await
}
