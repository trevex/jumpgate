//! jumpgate gateway: the single externally exposed data-plane entrypoint.
//!
//! Thin process wrapper over the `gateway` library crate: install the crypto
//! provider, load [`Config`], build the shared [`GatewayState`], spawn the roster
//! client and the health server, and run the external TLS accept loop, handing each
//! TLS-terminated connection to [`gateway::handle_connection`].

use std::sync::{Arc, RwLock};

use gateway::config::Config;
use gateway::lb::LoadCounters;
use gateway::roster::Roster;
use gateway::tls::{self, MeshClientCerts};
use gateway::{health, roster, GatewayState};
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

    // Read the mesh PEM material once; fail fast on bad/missing files.
    let mesh_certs =
        match MeshClientCerts::from_files(&config.mesh_cert, &config.mesh_key, &config.mesh_ca) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to load mesh client certificates");
                return Err(e);
            }
        };
    let server_config = tls::server_config(&config.tls_cert, &config.tls_key)?;

    let console_origin = gateway::terminal::OriginPolicy::from_env();
    if console_origin.is_unset() {
        tracing::warn!(
            "GATEWAY_CONSOLE_ORIGIN unset — the browser-terminal WebSocket endpoint allows any Origin (dev only)"
        );
    }

    let session_limits = gateway::proxy::SessionLimits {
        idle_timeout: config.session_idle_timeout,
        max_lifetime: config.session_max_lifetime,
    };
    tracing::info!(
        max_connections = config.max_connections,
        idle_timeout_secs = session_limits.idle_timeout.as_secs(),
        max_lifetime_secs = session_limits.max_lifetime.as_secs(),
        "gateway resource bounds",
    );

    let state = GatewayState {
        roster: Roster::default(),
        counters: LoadCounters::default(),
        mesh_certs,
        verification_key: Arc::new(RwLock::new(None)),
        console_origin: Arc::new(console_origin),
        session_limits,
    };

    // Roster client: stream worker updates + fetch the session verification key.
    tokio::spawn(roster::run(
        state.roster.clone(),
        config.warden_mesh_addr.clone(),
        config.warden_spiffe.clone(),
        state.mesh_certs.clone(),
        {
            let vk = state.verification_key.clone();
            move |k| {
                *vk.write().unwrap() = Some(k);
            }
        },
    ));

    // Health server on its own port.
    let health_addr = config.health_listen.clone();
    let health = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&health_addr).await?;
        tracing::info!(addr = %health_addr, "health server listening");
        axum::serve(listener, health::router()).await?;
        Ok::<(), anyhow::Error>(())
    });

    // External TLS listener.
    let external = tokio::spawn(run_external_listener(
        config.listen.clone(),
        server_config,
        state,
        config.max_connections,
    ));

    tokio::select! {
        r = health => r.map_err(anyhow::Error::from).and_then(|r| r)?,
        r = external => r.map_err(anyhow::Error::from).and_then(|r| r)?,
    }

    Ok(())
}

/// Bind the external TLS listener and dispatch each accepted connection to the
/// library's per-connection handler until failure.
async fn run_external_listener(
    addr: String,
    server_config: Arc<rustls::ServerConfig>,
    state: GatewayState,
    max_connections: usize,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // Bound concurrent external connections (and, since each holds its permit for
    // the life of its handler task, concurrent per-connection tasks). Acquiring a
    // permit BEFORE accepting the next socket applies natural backpressure once
    // we're at capacity, rather than accepting unboundedly.
    let limiter = Arc::new(tokio::sync::Semaphore::new(max_connections));
    tracing::info!(%addr, max_connections, "gateway external TLS listener ready");

    loop {
        // Wait for a free connection slot before accepting the next socket.
        let permit = match limiter.clone().acquire_owned().await {
            Ok(p) => p,
            // The semaphore is never closed; this is unreachable in practice.
            Err(_) => anyhow::bail!("connection limiter semaphore closed"),
        };
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                // Drop the permit (via the loop restart) so a transient accept
                // error doesn't leak a slot.
                drop(permit);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let st = state.clone();
        tokio::spawn(async move {
            // Held for the whole handler; released on task completion (normal
            // exit, TLS-handshake failure, or panic-unwind of the task).
            let _permit = permit;
            match acceptor.accept(tcp).await {
                Ok(tls) => gateway::handle_connection(st, tls).await,
                Err(e) => tracing::warn!(%peer, error = %e, "tls handshake failed"),
            }
        });
    }
}
