//! Browser-terminal ingress: a framed opcode protocol over the mesh stream.
//!
//! The gateway terminates the browser WebSocket and relays a length-delimited
//! opcode-frame protocol to this worker over the same mesh mTLS stream the SSH
//! ingress uses. When the CONNECT preamble carries `X-Jumpgate-Terminal: 1`, the
//! data-plane listener (see [`crate::server`]) runs [`run_terminal`] instead of
//! the russh SSH server.
//!
//! The terminal ingress REUSES the rest of the machinery unchanged: it redeems
//! the session with warden via [`crate::setup::setup_session`] (in `mode=web`, so
//! it passes an EMPTY client key and the ticket-bound login), dials the target
//! with the same [`crate::target`] helpers, records with the same
//! [`crate::record`] recorder, and registers/reports the live session on the same
//! control-plane seam. Only the *client-facing* transport differs: instead of a
//! russh channel it is a framed opcode stream.
//!
//! # Wire contract
//! Each frame is `[u32 BE len][opcode][payload]`, where `len` covers the opcode
//! byte plus the payload. Opcodes:
//! - inbound (browser→worker): `0x00 DATA`, `0x01 RESIZE` (JSON `{"cols","rows"}`),
//!   `0x02 PAUSE`, `0x03 RESUME`;
//! - outbound (worker→browser): `0x00 DATA`, `0x01 EXIT` (JSON `{"code"}`),
//!   `0x02 ERROR` (JSON `{"message"}`).

use std::sync::Arc;

use russh::ChannelMsg;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::asciicast::EventKind;
use crate::control::SessionRegistry;
use crate::record::RecorderHandle;
use crate::server::{
    build_recorder, dial_target_by_auth, unix_millis_now, RecordingOutcome, RecordingSettings,
    SessionEndReport, SessionState, SetupFn,
};
use crate::setup::setup_session;
use jumpgate_mesh::tls::MeshClientCerts;

/// Inbound opcode: raw terminal input bytes destined for the target's stdin.
pub const OP_IN_DATA: u8 = 0x00;
/// Inbound opcode: a terminal resize, payload `{"cols":N,"rows":M}` (JSON).
pub const OP_IN_RESIZE: u8 = 0x01;
/// Inbound opcode: flow-control pause (advisory; not currently acted on).
pub const OP_IN_PAUSE: u8 = 0x02;
/// Inbound opcode: flow-control resume (advisory; not currently acted on).
pub const OP_IN_RESUME: u8 = 0x03;

/// Outbound opcode: raw terminal output bytes from the target.
pub const OP_OUT_DATA: u8 = 0x00;
/// Outbound opcode: the target session ended, payload `{"code":N}` (JSON).
pub const OP_OUT_EXIT: u8 = 0x01;
/// Outbound opcode: a worker-side error, payload `{"message":"…"}` (JSON).
pub const OP_OUT_ERROR: u8 = 0x02;

/// A single terminal frame's length field caps the payload we will buffer, an
/// abuse guard against a peer announcing an enormous frame. 1 MiB is far larger
/// than any real terminal input frame.
pub const MAX_FRAME: u32 = 1024 * 1024;

/// Read one `[u32 BE len][opcode][payload]` frame from `r`.
///
/// Returns `(opcode, payload)`. A clean EOF at a frame boundary surfaces as an
/// `UnexpectedEof` error (the caller treats it as the client closing). A length
/// of zero (no opcode byte) or one exceeding [`MAX_FRAME`] is `InvalidData`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let len = r.read_u32().await?;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "terminal frame length 0 (no opcode)",
        ));
    }
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("terminal frame length {len} exceeds MAX_FRAME {MAX_FRAME}"),
        ));
    }
    let opcode = r.read_u8().await?;
    // `len` covers the opcode byte plus the payload.
    let payload_len = (len - 1) as usize;
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await?;
    Ok((opcode, payload))
}

/// Write one `[u32 BE len][opcode][payload]` frame to `w` (not flushed).
///
/// `len` is `payload.len() + 1` (opcode). Errors if the payload is too large to
/// frame within [`MAX_FRAME`].
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload
        .len()
        .checked_add(1)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n <= MAX_FRAME)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "terminal frame payload too large to encode",
            )
        })?;
    w.write_u32(len).await?;
    w.write_u8(opcode).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// A browser-sent terminal size (the `0x01 RESIZE` payload), deserialized from
/// `{"cols":N,"rows":M}`.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Resize {
    pub cols: u32,
    pub rows: u32,
}

/// Terminal dimensions applied to the target pty. Clamped to sane bounds so a
/// malformed or zero size never produces a degenerate pty (0 cols/rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u32,
    pub rows: u32,
}

/// The default pty size used when no resize arrives before the shell starts.
pub const DEFAULT_PTY: PtySize = PtySize { cols: 80, rows: 24 };

impl PtySize {
    /// Map a parsed [`Resize`] to a pty size, substituting the default for a
    /// zero/absent dimension (xterm.js occasionally reports 0 during layout).
    pub fn from_resize(r: Resize) -> PtySize {
        PtySize {
            cols: if r.cols == 0 {
                DEFAULT_PTY.cols
            } else {
                r.cols
            },
            rows: if r.rows == 0 {
                DEFAULT_PTY.rows
            } else {
                r.rows
            },
        }
    }
}

/// Parse a `0x01 RESIZE` JSON payload into a [`PtySize`], defaulting on any
/// malformed/zero dimension. Returns `None` only when the JSON itself is
/// unparseable (the caller keeps the current size).
pub fn parse_resize(payload: &[u8]) -> Option<PtySize> {
    let r: Resize = serde_json::from_slice(payload).ok()?;
    Some(PtySize::from_resize(r))
}

/// Encode the outbound `0x01 EXIT` payload `{"code":N}`.
pub fn exit_payload(code: u32) -> Vec<u8> {
    format!("{{\"code\":{code}}}").into_bytes()
}

/// Encode the outbound `0x02 ERROR` payload `{"message":"…"}` (message JSON-escaped).
pub fn error_payload(message: &str) -> Vec<u8> {
    // serde_json guarantees a valid JSON string literal; fall back to a fixed
    // message if (impossibly) serialization fails.
    let escaped =
        serde_json::to_string(message).unwrap_or_else(|_| "\"terminal error\"".to_string());
    format!("{{\"message\":{escaped}}}").into_bytes()
}

/// Everything the browser-terminal ingress needs to redeem a session and reach
/// warden — the mesh identity + warden coordinates + this worker's id, plus the
/// control-plane seam (registry + SessionEnded channel) and recording settings.
/// Assembled once by the data-plane listener and handed to [`run_terminal`] per
/// connection.
pub struct TerminalDeps {
    pub token: String,
    pub login: String,
    pub worker_id: String,
    pub warden_addr: String,
    pub warden_spiffe: String,
    pub certs: Arc<MeshClientCerts>,
    pub registry: SessionRegistry,
    pub session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
    pub recording: RecordingSettings,
}

impl TerminalDeps {
    /// Build the injected SetupSession fn for this connection — mirrors
    /// [`crate::server::SshHandler::new`] but the browser has no client key, so
    /// `authorize(login, None, …)` sends an empty `Kc` (warden's `mode=web` token
    /// skips the `cnf` proof and takes the login from the ticket).
    fn setup_fn(&self) -> SetupFn {
        let token = self.token.clone();
        let worker_id = self.worker_id.clone();
        let warden_addr = self.warden_addr.clone();
        let warden_spiffe = self.warden_spiffe.clone();
        let certs = self.certs.clone();
        Arc::new(move |login, kc_pub, kw_pub| {
            let token = token.clone();
            let worker_id = worker_id.clone();
            let warden_addr = warden_addr.clone();
            let warden_spiffe = warden_spiffe.clone();
            let certs = certs.clone();
            Box::pin(async move {
                setup_session(
                    &warden_addr,
                    &warden_spiffe,
                    &certs,
                    &token,
                    &worker_id,
                    &login,
                    kc_pub,
                    kw_pub,
                )
                .await
            })
        })
    }
}

/// Run the browser-terminal ingress over an already-authenticated mesh stream.
///
/// The gateway has read the CONNECT preamble (with `X-Jumpgate-Terminal: 1`),
/// answered `200`, and now relays the framed opcode protocol. This:
/// 1. redeems the session with warden (`mode=web`, empty client key) and
///    validates the target credential — REUSING [`crate::server::authorize`];
/// 2. builds the recorder (fail-closed when warden requires recording) — REUSING
///    [`crate::server::build_recorder`];
/// 3. dials the target and opens a pty+shell — REUSING
///    [`crate::server::dial_target_by_auth`] + the same [`crate::target`] helpers;
/// 4. registers the live session and pumps frames both ways, taps the recorder
///    identically to the SSH bridge, and on end finalizes the recording +
///    reports `SessionEnded` EXACTLY as the SSH path does.
///
/// `stream` is the mesh mTLS stream (an `AsyncRead + AsyncWrite`); the SSH-side
/// framing lives entirely inside this function.
pub async fn run_terminal<S>(deps: TerminalDeps, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let login = deps.login.clone();
    let setup = deps.setup_fn();

    let (mut reader, mut writer) = tokio::io::split(stream);

    // 1. Redeem the session (web mode: no client key). Any failure is a hard
    //    refuse — surface it to the browser as an ERROR frame and close.
    let state = match crate::server::authorize(&login, None, &setup).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(login = %login, error = %e, "terminal SetupSession rejected");
            send_error(&mut writer, "session setup failed").await;
            return;
        }
    };
    tracing::info!(session_id = %state.session_id, login = %login, "terminal session set up");

    // 2. Read the initial size: peek the first inbound frame. A leading RESIZE
    //    sets the pty; a leading DATA (or anything else) uses the 80x24 default
    //    and is replayed as the first pumped frame. A read error/EOF here means
    //    the client went away before sending anything.
    let (initial_size, pending_first): (PtySize, Option<(u8, Vec<u8>)>) = match read_frame(
        &mut reader,
    )
    .await
    {
        Ok((OP_IN_RESIZE, payload)) => (parse_resize(&payload).unwrap_or(DEFAULT_PTY), None),
        Ok(frame) => (DEFAULT_PTY, Some(frame)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            tracing::info!(session_id = %state.session_id, "terminal closed before first frame");
            return;
        }
        Err(e) => {
            tracing::warn!(session_id = %state.session_id, error = %e, "terminal read error before shell");
            send_error(&mut writer, "terminal read error").await;
            return;
        }
    };

    // 3. Recording decision BEFORE dialing the target — fail closed exactly like
    //    the SSH path: a required recording that can't be established refuses the
    //    session (report a failed recording, no bridge).
    let recorder = if state.recording_required {
        match build_recorder(
            &deps.recording,
            &state.recording_object_key,
            initial_size.cols as u16,
            initial_size.rows as u16,
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(session_id = %state.session_id, error = %e, "recording unavailable; refusing terminal session");
                let _ = deps.session_ended_tx.send(SessionEndReport {
                    session_id: state.session_id.clone(),
                    reason: "recording_unavailable".into(),
                    recording: Some(RecordingOutcome {
                        object_key: state.recording_object_key.clone(),
                        size_bytes: 0,
                        sha256: String::new(),
                        started_at_unix_ms: 0,
                        ended_at_unix_ms: 0,
                        status: "failed".into(),
                    }),
                });
                send_error(&mut writer, "recording unavailable").await;
                return;
            }
        }
    } else {
        None
    };

    // 4. Dial the target and open the pty+shell. On failure, finalize any recorder
    //    (fail) + report, and surface an ERROR — mirroring the SSH target-hop
    //    failure path.
    let (target_handle, target_channel) = match open_target_shell(&state, &login, initial_size)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(session_id = %state.session_id, error = %e, "terminal target hop failed");
            if let Some((handle, join, started_ms)) = recorder {
                handle.fail().await;
                let report = join.await.unwrap_or_else(|e| {
                        tracing::warn!(session_id = %state.session_id, error = %e, "recorder task join failed");
                        crate::record::RecordingReport {
                            size_bytes: 0,
                            sha256_hex: String::new(),
                            status: crate::record::RecordStatus::Failed,
                        }
                    });
                let _ = deps.session_ended_tx.send(SessionEndReport {
                    session_id: state.session_id.clone(),
                    reason: "target_unavailable".into(),
                    recording: Some(RecordingOutcome {
                        object_key: state.recording_object_key.clone(),
                        size_bytes: report.size_bytes,
                        sha256: report.sha256_hex,
                        started_at_unix_ms: started_ms,
                        ended_at_unix_ms: unix_millis_now(),
                        status: "failed".into(),
                    }),
                });
            }
            send_error(&mut writer, "target unavailable").await;
            return;
        }
    };

    // 5. Register the live session (so a Teardown force-closes it) and pump.
    let session_id = state.session_id.clone();
    let object_key = state.recording_object_key.clone();
    let handle = deps.registry.insert(&session_id);
    let registry = deps.registry.clone();
    let ended_tx = deps.session_ended_tx.clone();

    let (rec_handle, rec_join, started_ms) = match recorder {
        Some((h, j, s)) => (Some(h), Some(j), s),
        None => (None, None, 0),
    };

    let outcome = pump(
        &mut reader,
        &mut writer,
        target_channel,
        handle.cancel,
        rec_handle.clone(),
        started_ms,
        pending_first,
    )
    .await;
    let reason = outcome.reason();

    // 6. Finalize the recording EXACTLY as the SSH path: a clean end completes the
    //    upload, a recording failure aborts it; await the recorder for the report.
    let recording = if let (Some(h), Some(join)) = (rec_handle, rec_join) {
        if outcome == PumpOutcome::RecordingFailed {
            h.fail().await;
        } else {
            h.finish().await;
        }
        let report = join.await.unwrap_or_else(|e| {
            tracing::warn!(session_id = %session_id, error = %e, "recorder task join failed");
            crate::record::RecordingReport {
                size_bytes: 0,
                sha256_hex: String::new(),
                status: crate::record::RecordStatus::Failed,
            }
        });
        let status = match report.status {
            crate::record::RecordStatus::Completed => "completed",
            crate::record::RecordStatus::Failed => "failed",
        };
        Some(RecordingOutcome {
            object_key,
            size_bytes: report.size_bytes,
            sha256: report.sha256_hex,
            started_at_unix_ms: started_ms,
            ended_at_unix_ms: unix_millis_now(),
            status: status.into(),
        })
    } else {
        None
    };

    // 7. Exactly-once cleanup: drop from the registry, report the end once.
    registry.remove(&session_id);
    let _ = ended_tx.send(SessionEndReport {
        session_id: session_id.clone(),
        reason: reason.to_string(),
        recording,
    });
    drop(target_handle);
    tracing::info!(session_id = %session_id, reason, "terminal session ended");
}

/// How a terminal [`pump`] ended, so the caller reports the right `SessionEnded`
/// reason (mirrors [`crate::proxy::BridgeOutcome`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpOutcome {
    /// The control plane signalled a teardown.
    Terminated,
    /// The client or target closed naturally (frame EOF / channel close).
    Closed,
    /// A required recording could not keep up: fail closed.
    RecordingFailed,
}

impl PumpOutcome {
    fn reason(self) -> &'static str {
        match self {
            PumpOutcome::Terminated => "terminated",
            PumpOutcome::Closed => "closed",
            PumpOutcome::RecordingFailed => "recording_failed",
        }
    }
}

/// Dial the target and open a pty+shell sized to `size`. REUSES
/// [`dial_target_by_auth`] (identical target auth to the SSH path) then requests
/// a pty with the browser's initial size and a shell.
async fn open_target_shell(
    state: &SessionState,
    login: &str,
    size: PtySize,
) -> anyhow::Result<(
    russh::client::Handle<crate::target::TargetHandler>,
    russh::Channel<russh::client::Msg>,
)> {
    let handle = dial_target_by_auth(&state.target_address, login, &state.target_auth).await?;
    let target_channel = handle.channel_open_session().await?;
    // xterm-256color matches the terminal the browser xterm.js emulates; no pty
    // modes are negotiated (the browser has no local termios to mirror).
    target_channel
        .request_pty(false, "xterm-256color", size.cols, size.rows, 0, 0, &[])
        .await?;
    target_channel.request_shell(true).await?;
    Ok((handle, target_channel))
}

/// Record one frame into the recording, if active. Returns `true` when healthy
/// (no recorder or the event was accepted), `false` when a present recorder's
/// channel overflowed/closed — the fail-closed signal. Mirrors
/// [`crate::proxy`]'s tap so browser recordings are byte-identical to SSH ones.
fn tap(
    recorder: Option<&RecorderHandle>,
    start: std::time::Instant,
    kind: EventKind,
    data: Vec<u8>,
) -> bool {
    match recorder {
        Some(h) => h
            .try_event(start.elapsed().as_secs_f64(), kind, data)
            .is_ok(),
        None => true,
    }
}

/// Pump frames between the browser (framed opcode stream) and the target russh
/// channel until one side closes or `cancel` fires.
///
/// Inbound: `0x00 DATA` → target stdin; `0x01 RESIZE` → target `window_change`;
/// `0x02 PAUSE`/`0x03 RESUME` are advisory (ignored for now). Outbound: target
/// stdout/stderr → `0x00 DATA`; target `ExitStatus` → `0x01 EXIT {code}`. The
/// recorder taps input/output/resize exactly as [`crate::proxy::bridge`] does.
///
/// `pending_first` is a frame already read (when the leading frame was not the
/// initial RESIZE); it is processed before reading the next.
#[allow(clippy::too_many_arguments)]
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    target_channel: russh::Channel<russh::client::Msg>,
    cancel: Arc<tokio::sync::Notify>,
    recorder: Option<RecorderHandle>,
    _started_ms: i64,
    pending_first: Option<(u8, Vec<u8>)>,
) -> PumpOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut target_read, target_write) = target_channel.split();
    let start = std::time::Instant::now();

    let mut recording_failed = false;
    macro_rules! feed {
        ($kind:expr, $data:expr) => {
            if !tap(recorder.as_ref(), start, $kind, $data) {
                recording_failed = true;
            }
        };
    }

    // Process a leading DATA/other frame that was read while probing the initial
    // size, before entering the select loop.
    if let Some((opcode, payload)) = pending_first {
        match handle_inbound(opcode, payload, &target_write, start, recorder.as_ref()).await {
            Ok(false) => return PumpOutcome::RecordingFailed,
            Ok(true) => {}
            Err(e) => {
                tracing::warn!(error = %e, "terminal pending-first frame failed");
                return PumpOutcome::Closed;
            }
        }
    }

    let outcome;
    loop {
        tokio::select! {
            _ = cancel.notified() => {
                outcome = PumpOutcome::Terminated;
                break;
            }

            // Browser -> target.
            frame = read_frame(reader) => {
                match frame {
                    Ok((opcode, payload)) => {
                        match handle_inbound(opcode, payload, &target_write, start, recorder.as_ref()).await {
                            Ok(false) => { outcome = PumpOutcome::RecordingFailed; break; }
                            Ok(true) => {}
                            Err(e) => {
                                tracing::warn!(error = %e, "terminal inbound frame failed");
                                outcome = PumpOutcome::Closed;
                                break;
                            }
                        }
                    }
                    // EOF / read error: the browser closed the WS (relayed as a
                    // stream close). Natural close.
                    Err(_) => { outcome = PumpOutcome::Closed; break; }
                }
            }

            // Target -> browser.
            msg = target_read.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        feed!(EventKind::Output, data.to_vec());
                        if recording_failed { outcome = PumpOutcome::RecordingFailed; break; }
                        if write_frame(writer, OP_OUT_DATA, &data).await.is_err() {
                            outcome = PumpOutcome::Closed; break;
                        }
                        if writer.flush().await.is_err() { outcome = PumpOutcome::Closed; break; }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        feed!(EventKind::Output, data.to_vec());
                        if recording_failed { outcome = PumpOutcome::RecordingFailed; break; }
                        if write_frame(writer, OP_OUT_DATA, &data).await.is_err() {
                            outcome = PumpOutcome::Closed; break;
                        }
                        if writer.flush().await.is_err() { outcome = PumpOutcome::Closed; break; }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = write_frame(writer, OP_OUT_EXIT, &exit_payload(exit_status)).await;
                        let _ = writer.flush().await;
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, .. }) => {
                        tracing::info!(signal = ?signal_name, core_dumped, error_message = %error_message, "terminal target exited via signal");
                    }
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => { outcome = PumpOutcome::Closed; break; }
                    Some(_) => {}
                }
            }
        }
    }

    tracing::debug!(?outcome, "terminal pump finished; closing target channel");
    let _ = target_write.eof().await;
    let _ = target_write.close().await;
    outcome
}

/// Apply one inbound frame to the target. Returns `Ok(true)` on success,
/// `Ok(false)` when a required recording overflowed (fail-closed), and `Err` on a
/// target write failure. `PAUSE`/`RESUME` and unknown opcodes are ignored.
async fn handle_inbound(
    opcode: u8,
    payload: Vec<u8>,
    target_write: &russh::ChannelWriteHalf<russh::client::Msg>,
    start: std::time::Instant,
    recorder: Option<&RecorderHandle>,
) -> anyhow::Result<bool> {
    match opcode {
        OP_IN_DATA => {
            if !tap(recorder, start, EventKind::Input, payload.clone()) {
                return Ok(false);
            }
            target_write.data_bytes(payload).await?;
        }
        OP_IN_RESIZE => {
            if let Some(size) = parse_resize(&payload) {
                if !tap(
                    recorder,
                    start,
                    EventKind::Resize,
                    format!("{}x{}", size.cols, size.rows).into_bytes(),
                ) {
                    return Ok(false);
                }
                target_write
                    .window_change(size.cols, size.rows, 0, 0)
                    .await?;
            }
        }
        // Flow control is advisory today; the mesh stream already applies
        // backpressure. Unknown opcodes are ignored (forward-compatible).
        OP_IN_PAUSE | OP_IN_RESUME => {}
        _ => {}
    }
    Ok(true)
}

/// Best-effort ERROR frame to the browser before closing (setup/target failures
/// that occur before the pump). Ignores write errors — the peer may be gone.
async fn send_error<W: AsyncWrite + Unpin>(writer: &mut W, message: &str) {
    let _ = write_frame(writer, OP_OUT_ERROR, &error_payload(message)).await;
    let _ = writer.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round-trip through the framed codec: what `write_frame` emits, a
    /// `read_frame` on the same bytes recovers exactly.
    #[tokio::test]
    async fn frame_roundtrips() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, OP_IN_DATA, b"echo hi\n")
            .await
            .unwrap();
        write_frame(&mut buf, OP_IN_RESIZE, br#"{"cols":120,"rows":40}"#)
            .await
            .unwrap();
        write_frame(&mut buf, OP_IN_DATA, b"").await.unwrap(); // empty payload is legal

        let mut cur = std::io::Cursor::new(buf);
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_IN_DATA);
        assert_eq!(data, b"echo hi\n");
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_IN_RESIZE);
        assert_eq!(data, br#"{"cols":120,"rows":40}"#);
        let (op, data) = read_frame(&mut cur).await.unwrap();
        assert_eq!(op, OP_IN_DATA);
        assert!(data.is_empty());
    }

    /// The exact wire layout: `[u32 BE len][opcode][payload]`, len covering the
    /// opcode byte. Locks the byte-for-byte contract the gateway relays.
    #[tokio::test]
    async fn frame_wire_layout() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, OP_OUT_DATA, b"ok").await.unwrap();
        // len = 1 (opcode) + 2 (payload) = 3.
        assert_eq!(&buf, &[0, 0, 0, 3, OP_OUT_DATA, b'o', b'k']);
    }

    /// A payload split across two reads (the mesh stream may deliver a frame in
    /// pieces) must still be reassembled — `read_exact` handles the boundary.
    #[tokio::test]
    async fn frame_reassembles_across_reads() {
        // Frame: len=6 (opcode + 5-byte payload "hello").
        let full = {
            let mut b = Vec::new();
            write_frame(&mut b, OP_IN_DATA, b"hello").await.unwrap();
            b
        };
        // Feed the frame in two chunks with a real await boundary between them so
        // read_frame's read_u32/read_exact must span multiple polls.
        let (mut client, mut server) = tokio::io::duplex(64);
        let split = full.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&split[..3]).await.unwrap();
            client.flush().await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&split[3..]).await.unwrap();
            client.flush().await.unwrap();
        });
        let (op, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(op, OP_IN_DATA);
        assert_eq!(data, b"hello");
        writer.await.unwrap();
    }

    /// A length of zero (no opcode byte) is rejected as invalid data, not read as
    /// an empty frame.
    #[tokio::test]
    async fn zero_length_frame_is_invalid() {
        let buf = vec![0u8, 0, 0, 0]; // len = 0
        let mut cur = std::io::Cursor::new(buf);
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A length exceeding MAX_FRAME is rejected before allocating the payload.
    #[tokio::test]
    async fn oversized_length_is_invalid() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut cur = std::io::Cursor::new(buf);
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A clean EOF at a frame boundary surfaces as UnexpectedEof (the client
    /// closed the stream), which the handler treats as a normal close.
    #[tokio::test]
    async fn eof_at_boundary_is_unexpected_eof() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        let err = read_frame(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn resize_maps_to_pty() {
        let p = parse_resize(br#"{"cols":132,"rows":50}"#).unwrap();
        assert_eq!(
            p,
            PtySize {
                cols: 132,
                rows: 50
            }
        );
    }

    #[test]
    fn resize_zero_dimension_falls_back_to_default() {
        // A 0 in either dimension is replaced by the 80x24 default component.
        let p = parse_resize(br#"{"cols":0,"rows":40}"#).unwrap();
        assert_eq!(p, PtySize { cols: 80, rows: 40 });
        let p = parse_resize(br#"{"cols":100,"rows":0}"#).unwrap();
        assert_eq!(
            p,
            PtySize {
                cols: 100,
                rows: 24
            }
        );
    }

    #[test]
    fn resize_malformed_json_is_none() {
        assert!(parse_resize(b"not json").is_none());
        assert!(parse_resize(b"{}").is_none()); // missing fields
    }

    #[test]
    fn default_pty_is_80x24() {
        assert_eq!(DEFAULT_PTY, PtySize { cols: 80, rows: 24 });
    }

    #[test]
    fn exit_and_error_payloads_are_json() {
        assert_eq!(exit_payload(0), b"{\"code\":0}");
        assert_eq!(exit_payload(137), b"{\"code\":137}");
        let e = error_payload(r#"boom "quoted""#);
        // Round-trips as valid JSON with the message preserved.
        let v: serde_json::Value = serde_json::from_slice(&e).unwrap();
        assert_eq!(v["message"], r#"boom "quoted""#);
    }
}
