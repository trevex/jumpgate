//! jumpgate gateway library: the reusable connection-handling core.
//!
//! The binary (`main.rs`) is a thin process wrapper over this crate: it loads
//! configuration, builds the shared [`GatewayState`], spawns the roster client and
//! the health server, and drives the external TLS accept loop. Each accepted,
//! TLS-terminated connection is handed to [`handle_connection`], which is also the
//! seam the integration tests drive directly.

pub mod config;
pub mod health;
pub mod lb;
pub mod proxy;
pub mod roster;
pub mod token;

// The mesh mTLS ([`tls`]), CONNECT framing ([`connect`]), and generated tonic
// clients ([`pb`]) live in the shared `jumpgate-mesh` crate — ONE copy of the
// reviewed SPIFFE-pinning verifier. Re-exported here so existing
// `crate::tls`/`crate::connect`/`crate::pb` (and the e2e test's
// `gateway::tls`/`gateway::connect`) paths keep resolving unchanged.
pub use jumpgate_mesh::{connect, pb, tls};

use std::sync::{Arc, RwLock};
use tokio_rustls::server::TlsStream;

/// Shared gateway state for the connection handler.
#[derive(Clone)]
pub struct GatewayState {
    pub roster: roster::Roster,
    pub counters: lb::LoadCounters,
    pub mesh_certs: tls::MeshClientCerts,
    pub verification_key: Arc<RwLock<Option<Vec<u8>>>>,
}

/// Handle one accepted, TLS-terminated client connection: read CONNECT, verify the
/// token, pick a worker, dial it (mTLS + CONNECT), reply 200, then pump bytes.
pub async fn handle_connection(state: GatewayState, mut client: TlsStream<tokio::net::TcpStream>) {
    use tokio::io::AsyncWriteExt;

    // 1. Read CONNECT + token.
    let req = match connect::read_connect(&mut client).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "bad CONNECT");
            let _ = client
                .write_all(&connect::response_status(400, "Bad Request"))
                .await;
            return;
        }
    };
    // 2. Verify the token offline (need the verification key).
    let key = { state.verification_key.read().unwrap().clone() };
    let key = match key {
        Some(k) => k,
        None => {
            let _ = client
                .write_all(&connect::response_status(503, "Service Unavailable"))
                .await;
            return;
        }
    };
    let claims = match token::verify(&req.token, &key) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "token verify failed");
            let _ = client
                .write_all(&connect::response_status(403, "Forbidden"))
                .await;
            return;
        }
    };
    // 3. Pick a worker for the protocol.
    let entries = state.roster.snapshot_for(&claims.proto);
    let entry = match lb::pick(&entries, &state.counters) {
        Some(e) => e.clone(),
        None => {
            tracing::warn!(proto = %claims.proto, "no worker available");
            let _ = client
                .write_all(&connect::response_status(502, "Bad Gateway"))
                .await;
            return;
        }
    };
    // 4. Reserve a load slot (RAII) + dial the worker.
    let _guard = state.counters.acquire(&entry.worker_id);
    let worker =
        match proxy::connect_worker(&entry, &state.mesh_certs, &req.token, &req.authority).await {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(worker = %entry.worker_id, error = %e, "worker dial failed");
                let _ = client
                    .write_all(&connect::response_status(502, "Bad Gateway"))
                    .await;
                return;
            }
        };
    // 5. Tell the client we're connected, then pump until either side closes.
    if client
        .write_all(connect::response_established())
        .await
        .is_err()
    {
        return;
    }
    if let Err(e) = proxy::pump(client, worker).await {
        tracing::debug!(error = %e, "pump ended");
    }
    // _guard drops here → decrements the worker's in-flight count.
}
