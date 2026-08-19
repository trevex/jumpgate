//! ssh-proxy data-plane front door.
//!
//! Accepts the gateway's mesh mTLS connection (client cert pinned to the
//! gateway's SPIFFE id), reads the HTTP/1.1 CONNECT preamble, and — for now —
//! logs and closes. The russh SSH server + SetupSession auth + target hop land
//! in later M4c tasks (7+).

use std::fs;

use anyhow::Context;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;

/// Bind the data-plane mTLS listener and dispatch each accepted gateway
/// connection: TLS-accept (gateway mTLS) → read CONNECT → log + close.
pub async fn run_dataplane_server(config: &Config) -> anyhow::Result<()> {
    let cert_pem = fs::read(&config.mesh_cert)
        .with_context(|| format!("read mesh cert {}", config.mesh_cert))?;
    let key_pem =
        fs::read(&config.mesh_key).with_context(|| format!("read mesh key {}", config.mesh_key))?;
    let ca_pem =
        fs::read(&config.mesh_ca).with_context(|| format!("read mesh CA {}", config.mesh_ca))?;

    let server_config = jumpgate_mesh::tls::server_config_mtls(
        &cert_pem,
        &key_pem,
        &ca_pem,
        &config.gateway_spiffe,
    )
    .context("build data-plane mTLS server config")?;
    let acceptor = TlsAcceptor::from(server_config);

    let listener = tokio::net::TcpListener::bind(&config.dataplane_addr)
        .await
        .with_context(|| format!("bind data-plane listener {}", config.dataplane_addr))?;
    tracing::info!(
        addr = %config.dataplane_addr,
        gateway_spiffe = %config.gateway_spiffe,
        "ssh-proxy data-plane mTLS listener ready",
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(acceptor, tcp, peer).await {
                tracing::warn!(%peer, error = %e, "data-plane connection failed");
            }
        });
    }
}

/// Per-connection handler: TLS handshake (gateway mTLS), read the CONNECT
/// preamble, then log and drop (close). SSH server lands in Task 7.
async fn handle_conn(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut tls = acceptor
        .accept(tcp)
        .await
        .context("gateway mTLS handshake failed")?;

    let req = jumpgate_mesh::connect::read_connect(&mut tls)
        .await
        .context("read CONNECT preamble")?;

    tracing::info!(%peer, authority = %req.authority, "gateway CONNECT received");
    // For now: drop `tls` (and the parsed token) to close the connection. The
    // russh SSH server + SetupSession token auth land in Task 7.
    Ok(())
}
