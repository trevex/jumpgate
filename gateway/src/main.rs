//! jumpgate gateway: the single externally exposed data-plane entrypoint.
//!
//! M4b bootstrap: load [`Config`] from the environment, serve `/healthz` on its
//! own port, and run the external TLS listener. The per-connection handler is a
//! stub for now (complete handshake, log, close); CONNECT parsing, token
//! verification, load-balancing and the worker proxy land in later tasks.

mod config;
mod connect;
mod health;
mod tls;

use std::sync::Arc;

use config::Config;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // rustls 0.23 requires a process-wide default crypto provider. We use the
    // `ring` provider (no C toolchain needed, unlike aws-lc-rs).
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))?;

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "invalid gateway configuration");
            return Err(e);
        }
    };
    tracing::info!(
        listen = %config.listen,
        health_listen = %config.health_listen,
        warden_mesh_addr = %config.warden_mesh_addr,
        "gateway starting",
    );

    let server_config = tls::server_config(&config.tls_cert, &config.tls_key)?;
    // Built here to fail fast on bad mesh material; wired to the roster client
    // and worker proxy in later tasks.
    let _mesh_config =
        tls::mesh_client_config(&config.mesh_cert, &config.mesh_key, &config.mesh_ca)?;

    // Health server on its own port.
    let health_addr = config.health_listen.clone();
    let health = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&health_addr).await?;
        tracing::info!(addr = %health_addr, "health server listening");
        axum::serve(listener, health::router()).await?;
        Ok::<(), anyhow::Error>(())
    });

    // External TLS listener.
    let external = tokio::spawn(run_external_listener(config.listen.clone(), server_config));

    tokio::select! {
        r = health => r.map_err(anyhow::Error::from).and_then(|r| r)?,
        r = external => r.map_err(anyhow::Error::from).and_then(|r| r)?,
    }

    Ok(())
}

/// Bind the external TLS listener and handle connections until failure.
async fn run_external_listener(
    addr: String,
    server_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "gateway external TLS listener ready");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            handle_conn(acceptor, stream, peer).await;
        });
    }
}

/// Per-connection handler stub: complete the TLS handshake, log, and close.
/// Replaced by the real CONNECT→verify→pick→pump handler in a later task.
async fn handle_conn(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) {
    match acceptor.accept(stream).await {
        Ok(_tls_stream) => {
            tracing::info!(%peer, "accepted TLS connection");
            // Stub: drop the stream to close the connection.
        }
        Err(e) => {
            tracing::warn!(%peer, error = %e, "TLS handshake failed");
        }
    }
}
