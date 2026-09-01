//! jumpgate ssh-proxy worker: the SSH data-plane worker behind the gateway.
//!
//! Thin process wrapper over the `ssh_proxy` library crate: install the crypto
//! provider, init tracing, load [`Config`], and run the data-plane mTLS server.

use std::sync::Arc;

use ssh_proxy::config::Config;
use ssh_proxy::control::{run_control, SessionRegistry};
use ssh_proxy::server::{run_dataplane_server, run_health_listener};
use tokio::sync::Notify;

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
        require_host_key_pin = config.require_host_key_pin,
        "ssh-proxy starting",
    );

    // Install the deploy-time host-key policy before any target hop runs.
    ssh_proxy::target::set_require_host_key_pin(config.require_host_key_pin);

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

    // Graceful shutdown: on ctrl-c / SIGTERM, tell the data-plane server to stop
    // accepting and force-close its live sessions, then return.
    let shutdown = Arc::new(Notify::new());
    tokio::spawn(watch_for_signals(shutdown.clone()));

    // Plaintext health listener for kubelet probes: the data-plane port is mesh
    // mTLS and cannot be probed by a bare TCP `tcpSocket` probe.
    let health_addr = config.health_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = run_health_listener(&health_addr).await {
            tracing::error!(error = %e, "health listener exited");
        }
    });

    run_dataplane_server(&config, registry, session_ended_tx, shutdown).await
}

/// Wait for ctrl-c or SIGTERM and fire `shutdown`. On platforms without a SIGTERM
/// stream we fall back to ctrl-c alone.
async fn watch_for_signals(shutdown: Arc<Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGTERM handler; ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
                shutdown.notify_waiters();
                return;
            }
        };
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                if let Err(e) = r {
                    tracing::warn!(error = %e, "ctrl-c handler failed");
                }
                tracing::info!("received ctrl-c; shutting down");
            }
            _ = term.recv() => {
                tracing::info!("received SIGTERM; shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "ctrl-c handler failed");
        }
        tracing::info!("received ctrl-c; shutting down");
    }
    shutdown.notify_waiters();
}
