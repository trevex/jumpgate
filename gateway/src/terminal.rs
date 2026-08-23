//! Browser-terminal endpoint: accept a `GET /terminal?ticket=…` WebSocket on the
//! already-TLS-terminated external listener and relay it to an ssh-proxy worker's
//! framed-terminal ingress over the mesh.
//!
//! The external listener normally reads an HTTP `CONNECT` (the CLI tunnel; see
//! [`crate::handle_connection`]). When the request line is instead a
//! `GET /terminal…` with an `Upgrade: websocket`, control lands here:
//!
//! 1. The WebSocket handshake is completed on the raw `TlsStream` with
//!    [`tokio_tungstenite::accept_hdr_async`]; a header callback validates the
//!    request's `Origin` against a configured allowlist and captures the `ticket`
//!    query parameter. A bad `Origin` rejects the handshake with `403`.
//! 2. The ticket is verified offline ([`crate::token::verify`]); it MUST be a
//!    `mode="web"` ticket (browser tickets carry no client key). Anything else —
//!    wrong mode, expired, bad signature — closes the WebSocket.
//! 3. A worker is picked ([`crate::lb::pick`]) and mesh-dialed
//!    ([`crate::proxy::connect_worker_terminal`]) with the terminal CONNECT
//!    preamble (`X-Jumpgate-Terminal: 1` + `X-Jumpgate-Login: <ticket login>`).
//! 4. Frames are relayed 1:1 in both directions: each browser binary WebSocket
//!    message becomes one `[u32 BE len][frame]` on the mesh stream and vice versa.
//!    The gateway never interprets an opcode; the worker owns the terminal
//!    semantics (see `workers/ssh-proxy/src/terminal.rs`).
//!
//! # Wire contract (shared with the worker)
//! Browser↔gateway: one binary WebSocket message per frame (`[opcode][payload]`).
//! Gateway↔worker: `[u32 BE len][opcode][payload]`, `len` covering opcode+payload.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as WsRequest, Response as WsResponse,
};
use tokio_tungstenite::tungstenite::Message;

use crate::proxy::{SessionLimits, StopReason};
use crate::{lb, proxy, token, GatewayState};

/// A single relayed frame's length field caps what we buffer from the worker, an
/// abuse guard mirroring the worker's own `MAX_FRAME`. 1 MiB dwarfs any real
/// terminal frame.
pub const MAX_FRAME: u32 = 1024 * 1024;

/// Keepalive: send a WebSocket ping if no frame has flowed for this long, so idle
/// browser sessions survive intermediary idle timeouts.
const KEEPALIVE: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Origin allowlist (pure)
// ---------------------------------------------------------------------------

/// The configured browser-console `Origin` allowlist, parsed from
/// `GATEWAY_CONSOLE_ORIGIN` (comma-separated). An empty allowlist means "unset":
/// [`OriginPolicy::allow`] permits any origin (dev convenience) and the caller
/// logs a warning.
#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    allowed: Vec<String>,
}

impl OriginPolicy {
    /// Parse the comma-separated `GATEWAY_CONSOLE_ORIGIN` value. Whitespace around
    /// each entry is trimmed; empty entries are dropped.
    pub fn parse(raw: &str) -> Self {
        let allowed = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        OriginPolicy { allowed }
    }

    /// Read the policy from the environment (`GATEWAY_CONSOLE_ORIGIN`). Absent →
    /// an empty (allow-all-with-warning) policy.
    pub fn from_env() -> Self {
        match std::env::var("GATEWAY_CONSOLE_ORIGIN") {
            Ok(v) => Self::parse(&v),
            Err(_) => OriginPolicy::default(),
        }
    }

    /// `true` when no origins are configured (dev mode: allow all, warn).
    pub fn is_unset(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Decide whether a request's `Origin` header value is permitted.
    ///
    /// - Unset policy → always allowed (dev; the caller warns once per request).
    /// - Configured policy → the `Origin` must be present AND exactly match one
    ///   configured entry (a missing `Origin` against a configured allowlist is
    ///   denied — same-origin browser requests always send `Origin` for WS).
    pub fn allow(&self, origin: Option<&str>) -> bool {
        if self.allowed.is_empty() {
            return true;
        }
        match origin {
            Some(o) => self.allowed.iter().any(|a| a == o),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Request parsing (pure)
// ---------------------------------------------------------------------------

/// Extract the `ticket` query parameter from a request target/URI (e.g.
/// `/terminal?ticket=v4.public.xxx`). Returns `None` when absent or empty.
///
/// Session tokens are `v4.public.<base64url>` — no characters that require
/// percent-decoding — so the raw value is used as-is.
pub fn extract_ticket(uri: &http::Uri) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k == "ticket" && !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// `true` when the request path is the terminal endpoint (`/terminal`, ignoring
/// the query string). Lets the branch reject stray WS paths.
pub fn is_terminal_path(uri: &http::Uri) -> bool {
    uri.path() == "/terminal"
}

/// Read the `Origin` header value (borrowed, lossy-utf8-free: non-utf8 → `None`).
fn origin_header(req: &WsRequest) -> Option<&str> {
    req.headers().get(http::header::ORIGIN)?.to_str().ok()
}

// ---------------------------------------------------------------------------
// PrefixedStream: replay already-read head bytes before the live stream
// ---------------------------------------------------------------------------

/// Wraps a stream so that a buffer of already-consumed bytes is yielded first,
/// then reads fall through to the inner stream. The external listener peeks the
/// request head to branch CONNECT vs WS; for the WS branch those head bytes must
/// be replayed into `accept_hdr_async`, which reads the handshake itself.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Length-delimited frame IO on the mesh stream
// ---------------------------------------------------------------------------

/// Read one `[u32 BE len][frame]` from the worker mesh stream, returning the
/// `frame` bytes (`[opcode][payload]`, `len` bytes). A clean EOF at a frame
/// boundary surfaces as `UnexpectedEof`; an out-of-range length is `InvalidData`.
/// The gateway does NOT interpret the frame — it relays it verbatim to the WS.
async fn read_len_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let len = r.read_u32().await?;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("relayed frame length {len} out of range (0, {MAX_FRAME}]"),
        ));
    }
    let mut frame = vec![0u8; len as usize];
    r.read_exact(&mut frame).await?;
    Ok(frame)
}

/// Write one `[u32 BE len][frame]` to the worker mesh stream (not flushed). The
/// `frame` is the verbatim WebSocket binary payload (`[opcode][payload]`).
async fn write_len_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(frame.len())
        .ok()
        .filter(|n| *n != 0 && *n <= MAX_FRAME)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "relayed WS frame too large or empty",
            )
        })?;
    w.write_u32(len).await?;
    w.write_all(frame).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Handle a browser-terminal request on the external TLS listener.
///
/// `head` is the request bytes already read while branching CONNECT vs WS; they
/// are replayed into the WebSocket handshake. This completes the handshake
/// (validating `Origin` + capturing `ticket`), verifies the ticket is
/// `mode="web"`, picks + mesh-dials a worker with the terminal preamble, and
/// relays frames until either side closes.
// The handshake callback's `Result<Response, ErrorResponse>` type is dictated by
// tokio-tungstenite's `Callback` API; the large `Err` variant is unavoidable.
#[allow(clippy::result_large_err)]
pub async fn handle_terminal<S>(
    state: GatewayState,
    head: Vec<u8>,
    stream: S,
    origin_policy: Arc<OriginPolicy>,
    limits: SessionLimits,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let prefixed = PrefixedStream::new(head, stream);

    // Capture the ticket + Origin decision from the handshake request. The
    // callback runs synchronously during `accept_hdr_async`; it can reject the
    // handshake (bad Origin / wrong path) by returning an error response.
    let mut captured_ticket: Option<String> = None;
    let ticket_slot = &mut captured_ticket;
    let policy = origin_policy.clone();

    let ws = match tokio_tungstenite::accept_hdr_async(
        prefixed,
        |req: &WsRequest, resp: WsResponse| -> Result<WsResponse, ErrorResponse> {
            if !is_terminal_path(req.uri()) {
                return Err(reject(http::StatusCode::NOT_FOUND, "not found"));
            }
            let origin = origin_header(req);
            if !policy.allow(origin) {
                tracing::warn!(origin = ?origin, "terminal WS rejected: Origin not allowed");
                return Err(reject(http::StatusCode::FORBIDDEN, "origin not allowed"));
            }
            if policy.is_unset() {
                tracing::warn!(
                    "GATEWAY_CONSOLE_ORIGIN unset — allowing any WebSocket Origin (dev only)"
                );
            }
            *ticket_slot = extract_ticket(req.uri());
            Ok(resp)
        },
    )
    .await
    {
        Ok(ws) => ws,
        Err(e) => {
            // The handshake itself failed (bad request, or our callback rejected
            // it). tokio-tungstenite has already written the response.
            tracing::warn!(error = %e, "terminal WebSocket handshake failed");
            return;
        }
    };

    let ticket = match captured_ticket {
        Some(t) => t,
        None => {
            tracing::warn!("terminal WS missing ticket query param");
            close_ws(ws, "missing ticket").await;
            return;
        }
    };

    // Verify the ticket offline. It MUST be a web-mode ticket.
    let key = { state.verification_key.read().unwrap().clone() };
    let key = match key {
        Some(k) => k,
        None => {
            tracing::warn!("terminal WS: no verification key yet");
            close_ws(ws, "service unavailable").await;
            return;
        }
    };
    let claims = match token::verify(&ticket, &key) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "terminal ticket verify failed");
            close_ws(ws, "invalid ticket").await;
            return;
        }
    };
    if claims.mode != "web" {
        tracing::warn!(mode = %claims.mode, "terminal ticket is not mode=web");
        close_ws(ws, "invalid ticket mode").await;
        return;
    }
    let login = claims.login.clone();
    if login.is_empty() {
        tracing::warn!(session_id = %claims.session_id, "web ticket has no bound login");
        close_ws(ws, "invalid ticket login").await;
        return;
    }

    // Pick + mesh-dial a worker for the protocol, sending the terminal preamble.
    let entries = state.roster.snapshot_for(&claims.proto);
    let entry = match lb::pick(&entries, &state.counters) {
        Some(e) => e.clone(),
        None => {
            tracing::warn!(proto = %claims.proto, "terminal: no worker available");
            close_ws(ws, "no worker available").await;
            return;
        }
    };
    let _guard = state.counters.acquire(&entry.worker_id);
    let worker = match proxy::connect_worker_terminal(
        &entry,
        &state.mesh_certs,
        &ticket,
        &claims.asset_id,
        &login,
    )
    .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(worker = %entry.worker_id, error = %e, "terminal worker dial failed");
            close_ws(ws, "worker unavailable").await;
            return;
        }
    };

    tracing::info!(
        session_id = %claims.session_id,
        worker = %entry.worker_id,
        login = %login,
        "terminal session relay established"
    );

    match relay(ws, worker, limits).await {
        Ok(StopReason::Closed) => {}
        Ok(reason) => {
            tracing::info!(
                session_id = %claims.session_id,
                worker = %entry.worker_id,
                ?reason,
                "terminal session ended by resource bound"
            );
        }
        Err(e) => tracing::debug!(error = %e, "terminal relay ended"),
    }
    // _guard drops here → decrements the worker's in-flight count.
}

/// Build a rejection response for the handshake callback with a plain-text body.
fn reject(code: http::StatusCode, msg: &str) -> ErrorResponse {
    let mut resp = http::Response::new(Some(msg.to_string()));
    *resp.status_mut() = code;
    resp
}

/// Best-effort close of a WebSocket before the relay starts (auth failures). The
/// close reason is advisory; the peer may already be gone.
async fn close_ws<S>(mut ws: tokio_tungstenite::WebSocketStream<S>, reason: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    let _ = ws
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: reason.to_string().into(),
        })))
        .await;
    let _ = ws.close(None).await;
}

/// Relay frames between the browser WebSocket and the worker mesh stream until
/// either side closes.
///
/// - browser `Message::Binary(b)` → `[u32 BE len][b]` to the worker;
/// - worker `[u32 BE len][frame]` → browser `Message::Binary(frame)`;
/// - browser `Ping` → `Pong`; `Close`/EOF (either side) → tear down both;
/// - a ~30s keepalive ping is sent when idle.
///
/// Bounded by `limits`: a session with no frames flowing in EITHER direction for
/// `idle_timeout` is torn down ([`StopReason::Idle`]); one exceeding
/// `max_lifetime` is torn down ([`StopReason::Lifetime`]). A zero [`Duration`]
/// disables the corresponding bound. The keepalive ping/pong is NOT counted as
/// activity, so a browser tab that's connected-but-silent still times out. On
/// every exit path the browser side is cleanly closed, so the caller's teardown
/// (drop the load guard) runs identically for a normal close and a bound trip.
///
/// Text and other WebSocket message types are ignored (the protocol is binary).
async fn relay<C, W>(
    ws: tokio_tungstenite::WebSocketStream<C>,
    mut worker: W,
    limits: SessionLimits,
) -> std::io::Result<StopReason>
where
    C: AsyncRead + AsyncWrite + Unpin,
    W: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick.
    keepalive.tick().await;

    // Absolute-lifetime deadline (if enabled). A far-future instant stands in for
    // "unlimited" so the select arm can always be present without extra branching.
    let start = tokio::time::Instant::now();
    let lifetime_deadline = if limits.max_lifetime.is_zero() {
        None
    } else {
        Some(start + limits.max_lifetime)
    };
    let lifetime_sleep = tokio::time::sleep_until(
        lifetime_deadline.unwrap_or_else(|| start + Duration::from_secs(3_600 * 24 * 365)),
    );
    tokio::pin!(lifetime_sleep);

    // Idle tracking: reset on any real DATA frame either direction.
    let mut last_activity = tokio::time::Instant::now();

    let stop = loop {
        tokio::select! {
            // Browser → worker.
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        last_activity = tokio::time::Instant::now();
                        write_len_frame(&mut worker, &data).await?;
                        worker.flush().await?;
                    }
                    Some(Ok(Message::Ping(p))) => {
                        ws_tx.send(Message::Pong(p)).await.map_err(ws_io_err)?;
                    }
                    // Pongs (our keepalive replies), Text, and anything else are
                    // ignored — the terminal protocol is binary only.
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_)))
                    | Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break StopReason::Closed,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "terminal WS read error");
                        break StopReason::Closed;
                    }
                }
            }

            // Worker → browser.
            frame = read_len_frame(&mut worker) => {
                match frame {
                    Ok(f) => {
                        last_activity = tokio::time::Instant::now();
                        ws_tx.send(Message::Binary(f.into())).await.map_err(ws_io_err)?;
                    }
                    // EOF / bad frame: the worker closed the mesh stream.
                    Err(_) => break StopReason::Closed,
                }
            }

            // Idle keepalive + idle-timeout check.
            _ = keepalive.tick() => {
                if !limits.idle_timeout.is_zero()
                    && last_activity.elapsed() >= limits.idle_timeout
                {
                    break StopReason::Idle;
                }
                if ws_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break StopReason::Closed;
                }
            }

            // Absolute lifetime cap (only fires when enabled — otherwise the
            // deadline is ~1y out and never reached before a normal close).
            _ = &mut lifetime_sleep, if lifetime_deadline.is_some() => {
                break StopReason::Lifetime;
            }
        }
    };

    // Cleanly close the browser side; ignore errors (peer may be gone). This runs
    // on EVERY exit path — normal close, idle, or lifetime — so teardown is uniform.
    let _ = ws_tx.send(Message::Close(None)).await;
    let _ = ws_tx.close().await;
    Ok(stop)
}

/// Map a tungstenite send error to an `io::Error` for the relay's `Result`.
fn ws_io_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::other(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Origin policy ----------------------------------------------------

    #[test]
    fn unset_policy_allows_any_origin() {
        let p = OriginPolicy::parse("");
        assert!(p.is_unset());
        assert!(p.allow(Some("https://console.example")));
        assert!(p.allow(None));
    }

    #[test]
    fn configured_policy_matches_exact_origin() {
        let p = OriginPolicy::parse("https://console.example, http://localhost:8080");
        assert!(!p.is_unset());
        assert!(p.allow(Some("https://console.example")));
        assert!(p.allow(Some("http://localhost:8080")));
    }

    #[test]
    fn configured_policy_denies_other_and_missing_origin() {
        let p = OriginPolicy::parse("https://console.example");
        assert!(!p.allow(Some("https://evil.example")));
        assert!(!p.allow(Some("https://console.example.evil")));
        assert!(!p.allow(None)); // missing Origin against a configured allowlist
    }

    // ---- ticket / path parsing --------------------------------------------

    #[test]
    fn extracts_ticket_query_param() {
        let uri: http::Uri = "/terminal?ticket=v4.public.abc".parse().unwrap();
        assert_eq!(extract_ticket(&uri).as_deref(), Some("v4.public.abc"));
    }

    #[test]
    fn extracts_ticket_among_other_params() {
        let uri: http::Uri = "/terminal?foo=1&ticket=tok&bar=2".parse().unwrap();
        assert_eq!(extract_ticket(&uri).as_deref(), Some("tok"));
    }

    #[test]
    fn missing_or_empty_ticket_is_none() {
        let uri: http::Uri = "/terminal".parse().unwrap();
        assert_eq!(extract_ticket(&uri), None);
        let uri: http::Uri = "/terminal?ticket=".parse().unwrap();
        assert_eq!(extract_ticket(&uri), None);
    }

    #[test]
    fn terminal_path_recognised() {
        assert!(is_terminal_path(&"/terminal?ticket=x".parse().unwrap()));
        assert!(is_terminal_path(&"/terminal".parse().unwrap()));
        assert!(!is_terminal_path(&"/other".parse().unwrap()));
        assert!(!is_terminal_path(&"/terminal/extra".parse().unwrap()));
    }

    // ---- length-frame codec ----------------------------------------------

    #[test]
    fn len_frame_wire_layout() {
        // A 3-byte frame ([opcode][2-byte payload]) → 4-byte BE length prefix.
        let frame = vec![0x00u8, b'h', b'i'];
        let mut buf = Vec::new();
        futures_executor_block_on(write_len_frame(&mut buf, &frame)).unwrap();
        assert_eq!(&buf, &[0, 0, 0, 3, 0x00, b'h', b'i']);
    }

    #[tokio::test]
    async fn len_frames_round_trip_over_duplex() {
        // A sequence of WS binary payloads maps 1:1 to length-delimited frames
        // and back — exactly the translation the relay performs.
        let payloads: Vec<Vec<u8>> = vec![
            vec![0x00, b'l', b's', b'\n'],
            vec![0x01, b'{', b'}'],
            vec![0x00], // opcode-only frame (empty terminal payload)
            b"\x00a fairly long line of terminal output that spans a few dozen bytes".to_vec(),
        ];

        let (mut a, mut b) = tokio::io::duplex(64);
        let writes = payloads.clone();
        let writer = tokio::spawn(async move {
            for p in &writes {
                write_len_frame(&mut a, p).await.unwrap();
                a.flush().await.unwrap();
                // Yield so some frames split across reads on the peer.
                tokio::task::yield_now().await;
            }
            a.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        while let Ok(frame) = read_len_frame(&mut b).await {
            got.push(frame);
        }
        writer.await.unwrap();
        assert_eq!(got, payloads);
    }

    #[tokio::test]
    async fn read_len_frame_rejects_zero_length() {
        let buf = vec![0u8, 0, 0, 0];
        let mut cur = std::io::Cursor::new(buf);
        let err = read_len_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_len_frame_rejects_oversized() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut cur = std::io::Cursor::new(buf);
        let err = read_len_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_len_frame_eof_at_boundary() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        let err = read_len_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    // ---- PrefixedStream ---------------------------------------------------

    #[tokio::test]
    async fn prefixed_stream_yields_prefix_then_inner() {
        let (mut client, server) = tokio::io::duplex(64);
        // Inner stream will deliver " world" after the prefixed "hello".
        let writer = tokio::spawn(async move {
            client.write_all(b" world").await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut s = PrefixedStream::new(b"hello".to_vec(), server);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, b"hello world");
    }

    /// Minimal synchronous block-on for the one non-async codec test above,
    /// avoiding a full runtime for a pure buffer write.
    fn futures_executor_block_on<F: std::future::Future>(fut: F) -> F::Output {
        // The write futures against a `Vec` never actually suspend, so a trivial
        // no-op-waker poll loop resolves them immediately.
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
