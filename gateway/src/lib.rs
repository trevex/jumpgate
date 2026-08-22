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
pub mod terminal;
pub mod token;

// The mesh mTLS ([`tls`]), CONNECT framing ([`connect`]), and generated tonic
// clients ([`pb`]) live in the shared `jumpgate-mesh` crate — ONE copy of the
// reviewed SPIFFE-pinning verifier. Re-exported here so existing
// `crate::tls`/`crate::connect`/`crate::pb` (and the e2e test's
// `gateway::tls`/`gateway::connect`) paths keep resolving unchanged.
pub use jumpgate_mesh::{connect, pb, tls};

use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::server::TlsStream;

/// Shared gateway state for the connection handler.
#[derive(Clone)]
pub struct GatewayState {
    pub roster: roster::Roster,
    pub counters: lb::LoadCounters,
    pub mesh_certs: tls::MeshClientCerts,
    pub verification_key: Arc<RwLock<Option<Vec<u8>>>>,
    /// Allowed browser-console `Origin`s for the WebSocket terminal endpoint
    /// (`GATEWAY_CONSOLE_ORIGIN`). Empty = dev allow-all (with a warning).
    pub console_origin: Arc<terminal::OriginPolicy>,
}

/// Read the HTTP request head (up to the terminating `\r\n\r\n`), bounded by
/// [`connect::MAX_HEADER`]. Returns the buffered bytes so the caller can branch
/// on the request line without consuming the stream for the WS handshake.
async fn read_request_head<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > connect::MAX_HEADER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request header too large",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            // EOF before a full head: return what we have (parse will reject it).
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `true` when the request head is a `GET` with an `Upgrade: websocket` header —
/// the browser-terminal path. A plain `GET` (no upgrade) is not.
fn is_websocket_upgrade(head: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(head).is_err() {
        return false;
    }
    if !req
        .method
        .map(|m| m.eq_ignore_ascii_case("GET"))
        .unwrap_or(false)
    {
        return false;
    }
    req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(h.value)
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    })
}

/// Handle one accepted, TLS-terminated client connection.
///
/// Two ingresses share the external TLS listener: the CLI tunnel (HTTP `CONNECT`)
/// and the browser terminal (`GET /terminal?ticket=…` WebSocket upgrade). This
/// reads the request head, branches on the request line, and runs the matching
/// path. CONNECT → verify token, pick + dial a worker, reply 200, pump bytes.
pub async fn handle_connection(state: GatewayState, mut client: TlsStream<tokio::net::TcpStream>) {
    // Read the request head once so we can branch CONNECT vs WebSocket.
    let head = match read_request_head(&mut client).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "reading request head failed");
            let _ = client
                .write_all(&connect::response_status(400, "Bad Request"))
                .await;
            return;
        }
    };

    // Browser terminal: a WebSocket upgrade GET. The head is replayed into the
    // WS handshake, which reads the request itself.
    if is_websocket_upgrade(&head) {
        terminal::handle_terminal(state.clone(), head, client, state.console_origin.clone()).await;
        return;
    }

    // Otherwise: the CLI tunnel CONNECT. Parse the buffered head directly.
    let req = match connect::parse_connect(&head) {
        Ok(Some((r, _consumed))) => r,
        Ok(None) | Err(_) => {
            tracing::warn!("bad CONNECT / unrecognized request");
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
