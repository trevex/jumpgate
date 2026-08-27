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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    /// Idle + absolute-lifetime bounds applied to every proxied session (CONNECT
    /// byte pump and WS terminal relay), guarding against slow-loris / idle-hold.
    pub session_limits: proxy::SessionLimits,
}

/// Read the HTTP request head (up to the terminating `\r\n\r\n`), bounded by
/// [`connect::MAX_HEADER`]. Returns the buffered bytes so the caller can branch
/// on the request line without consuming the stream for the WS handshake.
async fn read_request_head<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    // Offset from which the next terminator scan starts. We only ever rescan the
    // freshly-appended bytes plus a 3-byte overlap (to catch a `\r\n\r\n` split
    // across two reads), so the total scan work is O(n) across the whole head
    // rather than O(n²) from re-scanning the accumulated buffer every read.
    let mut scan_from = 0usize;
    loop {
        if let Some(rel) = buf[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            // Terminator found; return the head (including the CRLFCRLF).
            let _ = rel; // position is relative; the full buffer is the head.
            return Ok(buf);
        }
        if buf.len() > connect::MAX_HEADER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request header too large",
            ));
        }
        // Next scan may start 3 bytes back so a terminator straddling this read
        // and the next is not missed.
        scan_from = buf.len().saturating_sub(3);
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

/// Handle one accepted client connection, generic over the transport stream.
///
/// Two ingresses share the external listener: the CLI tunnel (HTTP `CONNECT`)
/// and the browser terminal (`GET /terminal?ticket=…` WebSocket upgrade). This
/// reads the request head, branches on the request line, and runs the matching
/// path. CONNECT → verify token, pick + dial a worker, reply 200, pump bytes.
///
/// The stream is generic so the SAME handler (with the SAME ticket/token
/// verification) serves both the production TLS listener (`S = TlsStream`) and the
/// optional DEV-ONLY plaintext listener (`S = TcpStream`). Auth is never bypassed
/// on the plaintext path — only the transport encryption differs.
pub async fn handle_connection<S>(state: GatewayState, mut client: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
        let limits = state.session_limits;
        terminal::handle_terminal(
            state.clone(),
            head,
            client,
            state.console_origin.clone(),
            limits,
        )
        .await;
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
    match proxy::pump_bounded(client, worker, state.session_limits).await {
        Ok((_counts, proxy::StopReason::Closed)) => {}
        Ok((_counts, reason)) => {
            // Idle/lifetime bound tripped: a normal teardown, just observable.
            tracing::info!(worker = %entry.worker_id, ?reason, "session ended by resource bound");
        }
        Err(e) => tracing::debug!(error = %e, "pump ended"),
    }
    // _guard drops here → decrements the worker's in-flight count.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// An `AsyncRead` that yields a scripted sequence of byte chunks, one per
    /// `poll_read`, so we can force a header terminator to straddle two reads.
    struct ChunkReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            ChunkReader {
                chunks: chunks.into(),
            }
        }
    }

    impl AsyncRead for ChunkReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                // If the chunk didn't fit, push the remainder back for next poll.
                if n < chunk.len() {
                    self.chunks.push_front(chunk[n..].to_vec());
                }
            }
            // Empty deque → EOF (Ready with nothing filled).
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn header_scan_detects_terminator_split_across_reads() {
        // "\r\n\r\n" is split so that the first two bytes arrive in one read and
        // the last two in the next — the tail-rescan-with-overlap must still see it.
        let head = ChunkReader::new(vec![
            b"CONNECT asset-1 HTTP/1.1\r\nHost: x\r".to_vec(),
            b"\n\r\n".to_vec(),
            b"SHOULD-NOT-BE-READ".to_vec(),
        ]);
        let mut r = head;
        let out = read_request_head(&mut r).await.unwrap();
        assert!(out.ends_with(b"\r\n\r\n"), "terminator not detected");
        // The head stops at the terminator; trailing body bytes are not consumed.
        assert!(!out.windows(6).any(|w| w == b"SHOULD"));
    }

    #[tokio::test]
    async fn header_scan_detects_terminator_split_one_byte_per_read() {
        // Pathological: one byte per read. The overlap window must still catch a
        // terminator no matter how the reads chop it up.
        let bytes = b"GET /terminal HTTP/1.1\r\n\r\n";
        let chunks: Vec<Vec<u8>> = bytes.iter().map(|b| vec![*b]).collect();
        let mut r = ChunkReader::new(chunks);
        let out = read_request_head(&mut r).await.unwrap();
        assert_eq!(out, bytes);
    }

    #[tokio::test]
    async fn header_scan_rejects_oversized_header() {
        // A stream that never terminates: once the buffer exceeds MAX_HEADER the
        // read must fail with InvalidData rather than growing unbounded.
        let filler = vec![b'A'; 4096];
        let chunks = vec![filler.clone(), filler.clone(), filler.clone(), filler];
        let mut r = ChunkReader::new(chunks);
        let err = read_request_head(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn header_scan_eof_before_terminator_returns_partial() {
        let mut r = ChunkReader::new(vec![b"CONNECT x HTTP/1.1\r\n".to_vec()]);
        let out = read_request_head(&mut r).await.unwrap();
        assert_eq!(out, b"CONNECT x HTTP/1.1\r\n");
    }
}
