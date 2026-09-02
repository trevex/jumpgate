//! The RDCleanPath gateway: the worker terminates neither the RDP connector nor
//! the graphics session — the BROWSER runs the full IronRDP `ClientConnector` +
//! `ActiveStage`. The worker is an [RDCleanPath] server: it does the TCP + X.224 +
//! TLS hop to the target on the browser's behalf (so the browser never speaks TCP
//! or holds the target's TLS trust), returns the target's X.224 CC + certificate
//! chain, then relays PLAINTEXT RDP bidirectionally — INJECTING the vault
//! credentials into the browser's Client Info PDU so the browser never sees them.
//!
//! [RDCleanPath]: https://github.com/Devolutions/devolutions-gateway (mirrors
//! `devolutions-gateway/src/rd_clean_path.rs`).
//!
//! Flow (server side):
//! 1. Read the browser's RDCleanPath request off the mesh stream
//!    (`RDCleanPathPdu::detect` + `from_der`); take its `x224_connection_pdu` (CR).
//! 2. SECURITY: ignore the request's `destination`. The target is the
//!    warden/vault-resolved `target_address` — the browser must not pick it.
//! 3. TCP-connect the target, write the client's X.224 CR, read the target's
//!    X.224 CC (framed via `ironrdp_pdu::find_size`).
//! 4. TLS-upgrade to the target (verify against the pinned asset CA, else
//!    accept-any) and capture the peer certificate chain (DER).
//! 5. Write back `RDCleanPathPdu::new_response(target_addr, x224_cc, cert_chain)`.
//! 6. Relay plaintext RDP in two independent futures. Both directions are raw byte
//!    copies EXCEPT: (a) a one-shot Client Info injection on the browser→target
//!    path (credentials + `AUTOLOGON`), and (b) on the target→browser path, when
//!    warden requires a recording, the stream is framed PDU-by-PDU so the session
//!    can be recorded as `rdp-graphics-v1` (see [`record_relay_to_browser`]).
//!
//! Recording (target→browser) — the worker holds no `ConnectionResult` (the
//! browser runs the connector), so the `rdp-graphics-v1` [`Header`] is derived by
//! PARSING the relayed target→browser handshake tail with `ironrdp-pdu` 0.9:
//! * `io_channel_id` / `message_channel_id`: MCS Connect Response GCC server
//!   network / message-channel data (`mcs::ConnectResponse` →
//!   `conference_create_response.gcc_blocks().network.io_channel` /
//!   `.message_channel`). `io_channel_id` also falls back to the channel the
//!   Server Demand Active arrives on.
//! * `user_channel_id`: MCS Attach User Confirm (`mcs::AttachUserConfirm.initiator_id`).
//! * `width` / `height` / `share_id`: Server Demand Active (`decode_share_control`
//!   → `ShareControlPdu::ServerDemandActive`; desktop size from the Bitmap
//!   capability set, `share_id` from the share-control header).
//! * `compression`: the browser's own choice, read off the browser→target Client
//!   Info PDU (`ClientInfo.compression_type`, only meaningful with the
//!   `COMPRESSION` flag) — captured on the inject path and shared across.
//! * `enable_server_pointer` / `pointer_software_rendering`: client-only config,
//!   absent from the server stream — defaulted to match the browser's connector.
//!
//! The [`Header`] is complete by the Server Demand Active; recording STARTS at the
//! first PDU AFTER the server's Font Map (end of the connection-finalization
//! sequence), which is exactly the post-finalize server→client stream a fresh
//! replay `ActiveStage` consumes. Each recorded frame is fail-closed teed into the
//! recorder BEFORE it is forwarded (a frame that cannot be recorded is never
//! delivered).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context;
use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::mcs::{decode_send_data_indication, AttachUserConfirm, ConnectResponse, SendDataRequest};
use ironrdp_pdu::rdp::capability_sets::CapabilitySet;
use ironrdp_pdu::rdp::client_info::{ClientInfoFlags, CompressionType};
use ironrdp_pdu::rdp::headers::{decode_share_control, ShareControlPdu, ShareDataPdu};
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::x224::{X224, X224Data};
use ironrdp_pdu::Action;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPathPdu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::record::{
    spawn_recorder, PartUploader, RecordStatus, RecorderConfig, RecorderHandle, RecordingReport,
};
use crate::record_format::{self, Header};

/// How a [`run`] session ended, mapped to the `SessionEnded` reason string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The control plane signalled a teardown.
    Terminated,
    /// Either side closed naturally (browser WS close / target EOF).
    Closed,
    /// The target handshake failed (surfaced to the browser as an RDCleanPath
    /// error response where possible, else the stream is just closed).
    ConnectFailed,
    /// A required recording could not keep up (its channel overflowed/closed) or
    /// its [`Header`] could not be assembled: fail closed — the frame is never
    /// forwarded and the bridge tears down rather than run the session unrecorded.
    RecordingFailed,
}

impl BridgeOutcome {
    pub fn reason(self) -> &'static str {
        match self {
            BridgeOutcome::Terminated => "terminated",
            BridgeOutcome::Closed => "closed",
            BridgeOutcome::ConnectFailed => "target_unavailable",
            BridgeOutcome::RecordingFailed => "recording_failed",
        }
    }
}

/// A synthetic `Failed` report for a recording that was aborted before (or
/// without) any bytes being durably written — e.g. a target-connect failure after
/// the multipart upload was already opened caller-side, or a session that ended
/// during activation before the recorder was ever spawned.
fn failed_report() -> RecordingReport {
    RecordingReport {
        size_bytes: 0,
        sha256_hex: String::new(),
        status: RecordStatus::Failed,
    }
}

/// Current wall-clock time as unix milliseconds (saturating at 0 before the
/// epoch). Stamps the session's start timestamp.
fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The disposition of a finished [`run`]: the end outcome, the recording report
/// (if the session was recorded), and the session's start timestamp (unix ms). The
/// caller maps this to the `SessionEnded` proto, stamping the end timestamp.
pub struct RunReport {
    pub outcome: BridgeOutcome,
    pub recording: Option<RecordingReport>,
    pub started_at_unix_ms: i64,
}

/// The lifecycle of a required recording as it crosses the two relay futures. The
/// uploader is opened CALLER-side (fail-closed before dial); it is spawned into a
/// recorder only once the [`Header`] is assembled (at the server Font Map). Held
/// behind a mutex so the target→browser future can advance `Pending`→`Active` and
/// [`run`] can finalize whichever state the session ended in — regardless of which
/// direction's future won the `select!`.
enum RecState {
    /// Recording was not required.
    None,
    /// Required, but the recorder is not yet spawned (the graphics header has not
    /// been assembled). Carries the opened uploader.
    Pending(Box<dyn PartUploader>),
    /// The recorder task is running; carries the handle to finalize it and the
    /// join handle producing the authoritative [`RecordingReport`].
    Active(RecorderHandle, tokio::task::JoinHandle<RecordingReport>),
}

/// Run the RDCleanPath bridge over an already-authenticated mesh stream (the
/// gateway has read the CONNECT preamble, answered `200`, and now relays a raw
/// byte stream). Does the TCP+X.224+TLS hop to `target_address`, hands the browser
/// the target's X.224 CC + cert chain, then relays plaintext RDP with a one-shot
/// Client Info credential injection browser→target and — when `uploader` is
/// `Some` — a fail-closed `rdp-graphics-v1` recording of the target→browser stream.
///
/// `uploader` is opened by the CALLER before dialing (so a session that cannot be
/// recorded is refused before the target is ever contacted).
#[allow(clippy::too_many_arguments)]
pub async fn run<S>(
    target_address: &str,
    target_server_ca: &str,
    login: &str,
    password: &Zeroizing<String>,
    cancel: Arc<Notify>,
    stream: S,
    uploader: Option<Box<dyn PartUploader>>,
    rec_cfg: RecorderConfig,
) -> RunReport
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(stream);

    // On any failure BEFORE the relay starts, abort the (already opened, if any)
    // multipart upload so no dangling upload is left behind, and surface a
    // synthetic `Failed` report.
    macro_rules! refuse {
        ($outcome:expr) => {{
            let recording = match uploader {
                Some(u) => {
                    u.abort().await;
                    Some(failed_report())
                }
                None => None,
            };
            return RunReport {
                outcome: $outcome,
                recording,
                started_at_unix_ms: 0,
            };
        }};
    }

    // 1. Read the browser's RDCleanPath request off the mesh stream.
    let (request, leftover) = match read_cleanpath_request(&mut mesh_reader).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read RDCleanPath request");
            refuse!(BridgeOutcome::ConnectFailed);
        }
    };
    let x224_cr = match request.x224_connection_pdu {
        Some(os) => os.into_bytes(),
        None => {
            tracing::warn!("RDCleanPath request carried no X.224 connection PDU");
            send_error_response(&mut mesh_writer, RDCleanPathPdu::new_http_error(400)).await;
            refuse!(BridgeOutcome::ConnectFailed);
        }
    };

    // 2. SECURITY: the browser's `destination` is ignored. The target is the
    //    warden/vault-resolved address — the browser never dictates it.
    if let Some(dest) = request.destination.as_deref() {
        tracing::debug!(browser_destination = %dest, %target_address, "ignoring browser destination; using warden target");
    }
    let (host, port) = match split_host_port(target_address) {
        Some(v) => v,
        None => {
            tracing::warn!(%target_address, "malformed RDP target address");
            send_error_response(&mut mesh_writer, RDCleanPathPdu::new_http_error(500)).await;
            refuse!(BridgeOutcome::ConnectFailed);
        }
    };

    // 3. TCP-connect the target, forward the client's X.224 CR, read the CC.
    let (tcp, x224_cc) = match tcp_x224_exchange(&host, port, &x224_cr).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(%target_address, error = %e, "RDP target X.224 exchange failed");
            send_error_response(&mut mesh_writer, RDCleanPathPdu::new_http_error(502)).await;
            refuse!(BridgeOutcome::ConnectFailed);
        }
    };

    // 4. TLS-upgrade to the target, capturing its certificate chain (DER).
    let (tls_stream, cert_chain) = match tls_upgrade(tcp, &host, target_server_ca).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(%target_address, error = %e, "RDP target TLS upgrade failed");
            send_error_response(&mut mesh_writer, RDCleanPathPdu::new_tls_error(0)).await;
            refuse!(BridgeOutcome::ConnectFailed);
        }
    };

    // 5. Hand the browser the RDCleanPath response: target addr, X.224 CC, certs.
    let response =
        match RDCleanPathPdu::new_response(target_address.to_string(), x224_cc, cert_chain) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "failed to build RDCleanPath response");
                refuse!(BridgeOutcome::ConnectFailed);
            }
        };
    match response.to_der() {
        Ok(der) => {
            if mesh_writer.write_all(&der).await.is_err() || mesh_writer.flush().await.is_err() {
                refuse!(BridgeOutcome::Closed);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to encode RDCleanPath response");
            refuse!(BridgeOutcome::ConnectFailed);
        }
    }

    let started_at_unix_ms = unix_millis_now();
    tracing::info!(%target_address, "RDCleanPath established; relaying plaintext RDP");

    // 6. Relay plaintext RDP, each direction its own concurrently-polled future so
    //    a blocked write in one never head-of-line-blocks the other.
    let (mut target_read, mut target_write) = tokio::io::split(tls_stream);

    // Recording state shared across the two futures (see [`RecState`]). The
    // compression slot is set on the browser→target inject path (from the Client
    // Info PDU) and read on the target→browser path when the header is assembled.
    let rec_state = Arc::new(Mutex::new(match uploader {
        Some(u) => RecState::Pending(u),
        None => RecState::None,
    }));
    let comp_slot: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));

    // target → browser: raw copy when not recording; frame + fail-closed tee when
    // recording is required.
    let to_browser =
        record_relay_to_browser(&mut target_read, &mut mesh_writer, &comp_slot, &rec_state, rec_cfg);

    // browser → target: one-shot Client Info injection (capturing the browser's
    // compression choice), then raw pass-through.
    let to_target = inject_then_relay(
        &mut mesh_reader,
        &mut target_write,
        login,
        password,
        leftover,
        &comp_slot,
    );

    tokio::pin!(to_browser, to_target);
    let outcome = tokio::select! {
        _ = cancel.notified() => BridgeOutcome::Terminated,
        o = &mut to_browser => o,
        o = &mut to_target => o,
    };
    tracing::debug!(?outcome, "RDP relay finished");

    // Finalize the recording whatever direction ended the session: a clean end
    // (terminated / natural close) completes the upload; a recording failure aborts
    // it; a session that never reached the header aborts its pending upload.
    let recording = finalize_recording(&rec_state, outcome).await;

    RunReport {
        outcome,
        recording,
        started_at_unix_ms,
    }
}

/// Map an `ironrdp_pdu::Action` (the PDU framing discriminant returned by
/// `find_size`) to the `rdp-graphics-v1` action byte.
fn action_u8(a: Action) -> u8 {
    match a {
        Action::FastPath => record_format::ACTION_FASTPATH,
        Action::X224 => record_format::ACTION_X224,
    }
}

/// Assembles the `rdp-graphics-v1` [`Header`] by observing the relayed
/// target→browser handshake tail one PDU at a time. Fields are captured
/// opportunistically (each PDU shape is distinct; a failed decode simply means
/// "not this PDU"), and the header is complete by the Server Demand Active.
#[derive(Default)]
struct HeaderBuilder {
    io_channel_id: Option<u16>,
    user_channel_id: Option<u16>,
    message_channel_id: Option<u16>,
    desktop: Option<(u16, u16)>,
    share_id: Option<u32>,
}

impl HeaderBuilder {
    /// Feed one complete server→client PDU. Returns `true` iff this PDU was the
    /// server's Font Map (the end of connection finalization — recording begins
    /// with the NEXT PDU).
    fn observe(&mut self, pdu: &[u8]) -> bool {
        // MCS Connect Response → io + message channel ids (authoritative source,
        // matching the old ConnectionResult). Any X.224 data decodes as X224Data,
        // so the inner ConnectResponse decode is the real guard.
        // ponytail: the ConnectResponse arm is trusted-by-construction (mirrors
        // ironrdp-connector's own parse); not unit-covered — a BER Connect Response
        // is impractical to synthesize. io_channel_id is independently covered via
        // the Demand Active fallback below; message_channel_id (Option, None for
        // xrdp) rides this arm. Add a captured fixture to cover it if it regresses.
        if self.io_channel_id.is_none() {
            if let Ok(X224(x224_data)) = decode::<X224<X224Data<'_>>>(pdu) {
                if let Ok(cr) = decode::<ConnectResponse>(&x224_data.data) {
                    let gcc = cr.conference_create_response.gcc_blocks();
                    self.io_channel_id = Some(gcc.network.io_channel);
                    self.message_channel_id =
                        gcc.message_channel.as_ref().map(|m| m.mcs_message_channel_id);
                    return false;
                }
            }
        }

        // MCS Attach User Confirm → user channel id.
        if self.user_channel_id.is_none() {
            if let Ok(X224(auc)) = decode::<X224<AttachUserConfirm>>(pdu) {
                self.user_channel_id = Some(auc.initiator_id);
                return false;
            }
        }

        // Slow-path MCS Send Data Indication: either the Server Demand Active
        // (desktop size + share_id) or a share-data PDU (we only care about the
        // Font Map, which ends finalization).
        if let Ok(ctx) = decode_send_data_indication(pdu) {
            let channel_id = ctx.channel_id;
            if let Ok(sc) = decode_share_control(ctx) {
                match sc.pdu {
                    ShareControlPdu::ServerDemandActive(sda) => {
                        self.share_id.get_or_insert(sc.share_id);
                        // The Demand Active is sent on the I/O channel — a reliable
                        // fallback if the Connect Response was not parsed.
                        self.io_channel_id.get_or_insert(channel_id);
                        if self.desktop.is_none() {
                            self.desktop =
                                sda.pdu.capability_sets.iter().find_map(|c| match c {
                                    CapabilitySet::Bitmap(b) => {
                                        Some((b.desktop_width, b.desktop_height))
                                    }
                                    _ => None,
                                });
                        }
                    }
                    ShareControlPdu::Data(sdh) => {
                        if matches!(sdh.share_data_pdu, ShareDataPdu::FontMap(_)) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Build the seed [`Header`] once all required fields are present. `compression`
    /// is the browser's choice, captured off the Client Info PDU.
    fn build(&self, compression: u8) -> Option<Header> {
        let (width, height) = self.desktop?;
        Some(Header {
            width,
            height,
            user_channel_id: self.user_channel_id?,
            io_channel_id: self.io_channel_id?,
            message_channel_id: self.message_channel_id,
            share_id: self.share_id?,
            compression,
            // ponytail: client-only config, absent from the server stream. Defaulted
            // to the browser connector's own values (iron-remote-desktop-rdp /
            // IronRDP web `session.rs`: both false) so replay is seeded identically
            // to the live session. `enable_server_pointer=false` means the pointer
            // flags are inert for the recorded desktop bitmaps.
            enable_server_pointer: false,
            pointer_software_rendering: false,
        })
    }
}

/// Relay the target→browser direction. When recording is not required this is a
/// plain byte copy; when it is, the stream is framed PDU-by-PDU: activation PDUs
/// are forwarded raw while a [`HeaderBuilder`] assembles the seed header, and from
/// the first PDU after the server Font Map each PDU is fail-closed teed into the
/// recorder before being forwarded.
async fn record_relay_to_browser<R, W>(
    target_read: &mut R,
    mesh_writer: &mut W,
    comp_slot: &Mutex<Option<u8>>,
    rec_state: &Mutex<RecState>,
    rec_cfg: RecorderConfig,
) -> BridgeOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tmp = [0u8; 32 * 1024];

    // No recording required → raw copy, exactly as before.
    if matches!(&*rec_state.lock().unwrap(), RecState::None) {
        return raw_copy(target_read, mesh_writer, &mut tmp).await;
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut hb = HeaderBuilder::default();
    // The frame timer for `rdp-graphics-v1`, anchored when recording starts (at the
    // Font Map) so the first recorded frame is ~0ms.
    let mut start = Instant::now();
    // `Some` once the recorder is spawned (we are in the recording phase).
    let mut rec: Option<RecorderHandle> = None;

    loop {
        // Drain every complete PDU currently buffered.
        loop {
            let info = match ironrdp_pdu::find_size(&buf) {
                Ok(Some(info)) if buf.len() >= info.length => info,
                Ok(_) => break, // need more bytes
                Err(e) => {
                    // A required recording cannot frame the stream: fail closed
                    // rather than run (or record) a corrupt session.
                    // ponytail: not reachable on a valid post-TLS RDP stream.
                    tracing::warn!(error = %e, "could not frame server PDU; failing recording closed");
                    return BridgeOutcome::RecordingFailed;
                }
            };
            let pdu = buf[..info.length].to_vec();
            buf.drain(..info.length);

            if let Some(handle) = rec.as_ref() {
                // Recording phase: fail-closed tee BEFORE forwarding.
                let millis = start.elapsed().as_millis() as u64;
                if let Err(outcome) =
                    record_frame(handle, mesh_writer, millis, action_u8(info.action), &pdu).await
                {
                    return outcome;
                }
                continue;
            }

            // Activation phase: forward raw, feed the header parser.
            if mesh_writer.write_all(&pdu).await.is_err() || mesh_writer.flush().await.is_err() {
                return BridgeOutcome::Closed;
            }
            if hb.observe(&pdu) {
                // Server Font Map: finalization is done. The header is complete;
                // spawn the recorder and switch to the recording phase.
                let compression = comp_slot
                    .lock()
                    .unwrap()
                    .unwrap_or(record_format::compression::NONE);
                let header = match hb.build(compression) {
                    Some(h) => h,
                    None => {
                        tracing::warn!("recording required but session header incomplete; failing closed");
                        return BridgeOutcome::RecordingFailed;
                    }
                };
                let mut guard = rec_state.lock().unwrap();
                if let RecState::Pending(u) = std::mem::replace(&mut *guard, RecState::None) {
                    let (handle, join) = spawn_recorder(u, header, rec_cfg);
                    rec = Some(handle.clone());
                    *guard = RecState::Active(handle, join);
                }
                drop(guard);
                start = Instant::now();
                tracing::info!("RDP graphics header assembled; recording started");
            }
        }

        match target_read.read(&mut tmp).await {
            Ok(0) | Err(_) => return BridgeOutcome::Closed,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

/// Fail-closed tee of one server→client PDU: record it FIRST; only forward it to
/// the browser if it was accepted. `Err(RecordingFailed)` means the recorder could
/// not take the frame (channel full/closed) — the frame is NOT delivered.
/// `Err(Closed)` means the browser write failed. `Ok(())` means forwarded.
async fn record_frame<W>(
    handle: &RecorderHandle,
    mesh_writer: &mut W,
    millis: u64,
    action: u8,
    pdu: &[u8],
) -> Result<(), BridgeOutcome>
where
    W: AsyncWrite + Unpin,
{
    if handle.try_frame(millis, action, pdu.to_vec()).is_err() {
        return Err(BridgeOutcome::RecordingFailed);
    }
    if mesh_writer.write_all(pdu).await.is_err() || mesh_writer.flush().await.is_err() {
        return Err(BridgeOutcome::Closed);
    }
    Ok(())
}

/// Finalize the recording after the relay ends, from whatever [`RecState`] the
/// session is in. A clean end (`Terminated`/`Closed`) completes the upload; a
/// `RecordingFailed` outcome aborts it; a still-`Pending` upload (the session ended
/// during activation, before the recorder was spawned) is aborted and reported
/// failed. Returns `None` when recording was not required.
async fn finalize_recording(
    rec_state: &Mutex<RecState>,
    outcome: BridgeOutcome,
) -> Option<RecordingReport> {
    let state = std::mem::replace(&mut *rec_state.lock().unwrap(), RecState::None);
    match state {
        RecState::None => None,
        RecState::Pending(u) => {
            u.abort().await;
            Some(failed_report())
        }
        RecState::Active(handle, join) => {
            if outcome == BridgeOutcome::RecordingFailed {
                handle.fail().await;
            } else {
                handle.finish().await;
            }
            Some(join.await.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "recorder task join failed");
                failed_report()
            }))
        }
    }
}

/// Read one RDCleanPath PDU off the mesh stream, mirroring Devolutions'
/// `read_cleanpath_pdu`: accumulate bytes until `detect` frames a complete PDU,
/// then `from_der`. Any bytes past the PDU are returned as `leftover` (fed to the
/// browser→target relay so nothing the browser pipelined is dropped).
async fn read_cleanpath_request<R>(reader: &mut R) -> anyhow::Result<(RDCleanPathPdu, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 8192];
    loop {
        if let DetectionResult::Detected { total_length, .. } = RDCleanPathPdu::detect(&buf) {
            if buf.len() >= total_length {
                let pdu = RDCleanPathPdu::from_der(&buf[..total_length])
                    .map_err(|e| anyhow::anyhow!("decode RDCleanPath PDU: {e}"))?;
                let leftover = buf.split_off(total_length);
                return Ok((pdu, leftover));
            }
        } else if let DetectionResult::Failed = RDCleanPathPdu::detect(&buf) {
            anyhow::bail!("RDCleanPath detection failed");
        }
        let n = reader
            .read(&mut tmp)
            .await
            .context("read RDCleanPath bytes")?;
        if n == 0 {
            anyhow::bail!("EOF before a complete RDCleanPath PDU");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// TCP-connect the target, write the client's X.224 CR, and read the target's
/// X.224 CC (framed with `ironrdp_pdu::find_size`). Returns the (still plaintext)
/// TCP stream ready for the TLS upgrade, plus the CC bytes.
async fn tcp_x224_exchange(
    host: &str,
    port: u16,
    x224_cr: &[u8],
) -> anyhow::Result<(TcpStream, Vec<u8>)> {
    let mut tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("TCP connect to RDP target {host}:{port}"))?;
    tcp.write_all(x224_cr)
        .await
        .context("write X.224 CR to target")?;
    tcp.flush().await.context("flush X.224 CR to target")?;
    let x224_cc = read_x224_response(&mut tcp)
        .await
        .context("read X.224 CC from target")?;
    Ok((tcp, x224_cc))
}

/// Read one framed X.224 response (the connection confirm) from the target, using
/// `ironrdp_pdu::find_size` to find the PDU boundary. Mirrors Devolutions'
/// `read_x224_response`.
async fn read_x224_response<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    const MAX_READ_SIZE: usize = 512;
    let mut buf = vec![0u8; 19];
    let mut filled = 0;
    loop {
        if let Some(info) = ironrdp_pdu::find_size(&buf[..filled]).context("find X.224 PDU size")? {
            match filled.cmp(&info.length) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    buf.truncate(filled);
                    return Ok(buf);
                }
                std::cmp::Ordering::Greater => anyhow::bail!("received more than one X.224 PDU"),
            }
        }
        if filled == buf.len() {
            if buf.len() >= MAX_READ_SIZE {
                anyhow::bail!("X.224 response exceeds {MAX_READ_SIZE} bytes");
            }
            buf.resize(MAX_READ_SIZE, 0);
        }
        let n = reader
            .read(&mut buf[filled..])
            .await
            .context("read X.224 response bytes")?;
        if n == 0 {
            anyhow::bail!("EOF before a complete X.224 response");
        }
        filled += n;
    }
}

/// Locate the Client Info PDU on the browser→target byte stream, inject the vault
/// credentials + `AUTOLOGON`, capture the browser's compression choice into
/// `comp_slot`, forward it, then switch to raw pass-through for the rest of the
/// session. Everything before the Client Info PDU (the MCS connect sequence)
/// passes through unchanged; if the stream can't be framed, it degrades to raw
/// pass-through rather than wedging the session.
async fn inject_then_relay<R, W>(
    mesh_reader: &mut R,
    target_write: &mut W,
    login: &str,
    password: &str,
    mut buf: Vec<u8>,
    comp_slot: &Mutex<Option<u8>>,
) -> BridgeOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tmp = [0u8; 32 * 1024];
    loop {
        match ironrdp_pdu::find_size(&buf) {
            Ok(Some(info)) if buf.len() >= info.length => {
                // One complete PDU is buffered.
                if let Some((rewritten, compression)) =
                    rewrite_client_info(&buf[..info.length], login, password)
                {
                    // Found + injected the Client Info PDU. Record the browser's
                    // compression choice (read later when the recording header is
                    // assembled — the server Demand Active/Font Map that trigger it
                    // arrive only AFTER this PDU reaches the target, so the slot is
                    // always set in time). Then forward it, any already-buffered
                    // bytes, and raw-pump the rest.
                    *comp_slot.lock().unwrap() = Some(compression);
                    let rest = buf.split_off(info.length);
                    if target_write.write_all(&rewritten).await.is_err()
                        || (!rest.is_empty() && target_write.write_all(&rest).await.is_err())
                        || target_write.flush().await.is_err()
                    {
                        return BridgeOutcome::Closed;
                    }
                    tracing::debug!("injected vault credentials into Client Info PDU");
                    return raw_copy(mesh_reader, target_write, &mut tmp).await;
                }
                // Not the Client Info PDU (MCS connect sequence) — forward raw.
                if target_write.write_all(&buf[..info.length]).await.is_err()
                    || target_write.flush().await.is_err()
                {
                    return BridgeOutcome::Closed;
                }
                buf.drain(..info.length);
            }
            Ok(_) => {
                // Not enough bytes for a full PDU yet — read more.
                match mesh_reader.read(&mut tmp).await {
                    Ok(0) | Err(_) => return BridgeOutcome::Closed,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            Err(e) => {
                // Unframable input: don't wedge — forward what we have and go raw.
                // ponytail: giving up on injection means logon has no credentials;
                // only reachable on a malformed/unexpected client stream.
                tracing::warn!(error = %e, "could not frame client PDU; skipping Client Info injection");
                if !buf.is_empty() && target_write.write_all(&buf).await.is_err() {
                    return BridgeOutcome::Closed;
                }
                let _ = target_write.flush().await;
                return raw_copy(mesh_reader, target_write, &mut tmp).await;
            }
        }
    }
}

/// Raw byte copy from `reader` to `writer` until EOF/error. Used for both the
/// post-injection browser→target tail and the non-recording target→browser path.
async fn raw_copy<R, W>(reader: &mut R, writer: &mut W, tmp: &mut [u8]) -> BridgeOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match reader.read(tmp).await {
            Ok(0) | Err(_) => return BridgeOutcome::Closed,
            Ok(n) => {
                if writer.write_all(&tmp[..n]).await.is_err() || writer.flush().await.is_err() {
                    return BridgeOutcome::Closed;
                }
            }
        }
    }
}

/// If `pdu` is an X.224 data PDU wrapping an MCS `SendDataRequest` whose user data
/// is a `ClientInfoPdu`, replace its credentials with `login` + `password`, set
/// `AUTOLOGON`, and re-encode the whole X.224/MCS/ClientInfo stack. Returns the
/// re-encoded PDU together with the browser's `rdp-graphics-v1` compression
/// discriminant (the recorded stream's compression is the browser's advertised
/// choice). Returns `None` when `pdu` is not a Client Info PDU (any other PDU
/// passes through untouched).
///
/// Mirrors the connector's `create_client_info_pdu` wrapping (ironrdp-connector
/// `connection.rs`): `encode_send_data_request` wraps the `ClientInfoPdu` as the
/// user data of an MCS `SendDataRequest`, itself wrapped in `X224`.
fn rewrite_client_info(pdu: &[u8], login: &str, password: &str) -> Option<(Vec<u8>, u8)> {
    let X224(mut sdr) = decode::<X224<SendDataRequest>>(pdu).ok()?;
    let mut info = decode::<ClientInfoPdu>(&sdr.user_data[..]).ok()?;

    let compression = client_info_compression(&info);

    info.client_info.credentials.username = login.to_string();
    info.client_info.credentials.password = password.to_string();
    info.client_info.credentials.domain = None;
    info.client_info.flags |= ClientInfoFlags::AUTOLOGON;

    let new_user_data = encode_vec(&info).ok()?;
    sdr.user_data = std::borrow::Cow::Owned(new_user_data);
    Some((encode_vec(&X224(sdr)).ok()?, compression))
}

/// The `rdp-graphics-v1` compression discriminant the browser advertised. RDP only
/// uses bulk compression when the Client Info `COMPRESSION` flag is set; the
/// `compression_type` field is otherwise meaningless (defaults to `K8`), so it must
/// be gated on the flag — matching the connector's `ConnectionResult.compression_type`
/// (`Option`, `None` unless the flag is advertised).
fn client_info_compression(info: &ClientInfoPdu) -> u8 {
    use record_format::compression;
    if info.client_info.flags.contains(ClientInfoFlags::COMPRESSION) {
        match info.client_info.compression_type {
            CompressionType::K8 => compression::K8,
            CompressionType::K64 => compression::K64,
            CompressionType::Rdp6 => compression::RDP6,
            CompressionType::Rdp61 => compression::RDP61,
        }
    } else {
        compression::NONE
    }
}

/// Upgrade the target TCP stream to TLS and capture its certificate chain (DER).
/// When `target_server_ca` is non-empty the server cert is verified against it
/// (fail closed / MITM protection); empty = accept any (TOFU-off bring-up path).
// ponytail: accept-any is the DEFAULT when an asset pins no CA — a blank asset
// silently gets an unauthenticated target channel. Acceptable for bring-up; before
// GA, production RDP assets MUST require a pinned target_server_ca (enforce at
// asset-authoring or reject empty-CA at setup).
async fn tls_upgrade(
    stream: TcpStream,
    server_name: &str,
    target_server_ca: &str,
) -> anyhow::Result<(TlsStream<TcpStream>, Vec<Vec<u8>>)> {
    let mut config = if target_server_ca.trim().is_empty() {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        let mut pem = target_server_ca.as_bytes();
        for cert in rustls_pemfile::certs(&mut pem) {
            let cert = cert.context("parse target_server_ca PEM")?;
            roots.add(cert).context("add target CA to root store")?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    // RDP does not use TLS resumption; disable it (harmless when off too).
    config.resumption = rustls::client::Resumption::disabled();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let dns = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .with_context(|| format!("invalid TLS server name {server_name}"))?;
    let tls_stream = connector
        .connect(dns, stream)
        .await
        .context("TLS handshake with target")?;

    // Capture the peer certificate chain (DER) for the RDCleanPath response — the
    // browser needs it to complete its own connector (server public key binding).
    let cert_chain: Vec<Vec<u8>> = {
        let (_io, conn) = tls_stream.get_ref();
        conn.peer_certificates()
            .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            .unwrap_or_default()
    };

    Ok((tls_stream, cert_chain))
}

/// Best-effort RDCleanPath error response before closing (a handshake failure the
/// browser can surface). Ignores write errors — the peer may already be gone.
async fn send_error_response<W>(w: &mut W, pdu: RDCleanPathPdu)
where
    W: AsyncWrite + Unpin,
{
    if let Ok(der) = pdu.to_der() {
        let _ = w.write_all(&der).await;
        let _ = w.flush().await;
    }
}

/// Split a `host:port` target address. Returns `None` on a missing/empty host or
/// an unparseable port. (RDP targets are plain `host:port`; bracketed IPv6 is not
/// used by the catalog.)
fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Accept-any TLS verifier for the unpinned target path. Only reachable when the
/// asset configures no `target_server_ca`.
mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::{pki_types, DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_pdu::mcs::SendDataIndication;
    use ironrdp_pdu::rdp::capability_sets::{
        Bitmap, BitmapDrawingFlags, CapabilitySet, DemandActive, ServerDemandActive,
        SERVER_CHANNEL_ID,
    };
    use ironrdp_pdu::rdp::client_info::{
        AddressFamily, ClientInfo, ClientInfoFlags, CompressionType, Credentials,
        ExtendedClientInfo, ExtendedClientOptionalInfo,
    };
    use ironrdp_pdu::rdp::finalization_messages::FontPdu;
    use ironrdp_pdu::rdp::headers::{
        BasicSecurityHeader, BasicSecurityHeaderFlags, CompressionFlags, ShareControlHeader,
        ShareDataHeader, StreamPriority,
    };
    use std::borrow::Cow;

    #[test]
    fn split_host_port_parses() {
        assert_eq!(
            split_host_port("rdp.prod:3389"),
            Some(("rdp.prod".to_string(), 3389))
        );
        assert_eq!(
            split_host_port("10.0.0.5:3390"),
            Some(("10.0.0.5".to_string(), 3390))
        );
    }

    #[test]
    fn split_host_port_rejects_malformed() {
        assert_eq!(split_host_port("nohost"), None);
        assert_eq!(split_host_port(":3389"), None);
        assert_eq!(split_host_port("host:notaport"), None);
    }

    #[test]
    fn outcome_maps_to_session_ended_reason() {
        assert_eq!(BridgeOutcome::Terminated.reason(), "terminated");
        assert_eq!(BridgeOutcome::Closed.reason(), "closed");
        assert_eq!(BridgeOutcome::ConnectFailed.reason(), "target_unavailable");
        assert_eq!(BridgeOutcome::RecordingFailed.reason(), "recording_failed");
    }

    /// Wrap `user_data` as an MCS Send Data Indication on `channel_id` (the shape
    /// the server sends slow-path PDUs in), X.224-framed as it is on the wire.
    fn server_sdi(channel_id: u16, user_data: Vec<u8>) -> Vec<u8> {
        let sdi = SendDataIndication {
            initiator_id: SERVER_CHANNEL_ID,
            channel_id,
            user_data: Cow::Owned(user_data),
        };
        encode_vec(&X224(sdi)).expect("encode X224<SendDataIndication>")
    }

    /// A Server Demand Active PDU (share-control), carrying the desktop size (in the
    /// Bitmap capability set) and `share_id`, on the I/O channel.
    fn demand_active(io_channel_id: u16, share_id: u32, width: u16, height: u16) -> Vec<u8> {
        let sch = ShareControlHeader {
            share_control_pdu: ShareControlPdu::ServerDemandActive(ServerDemandActive {
                pdu: DemandActive {
                    source_descriptor: "RDP".to_owned(),
                    capability_sets: vec![CapabilitySet::Bitmap(Bitmap {
                        pref_bits_per_pix: 32,
                        desktop_width: width,
                        desktop_height: height,
                        desktop_resize_flag: true,
                        drawing_flags: BitmapDrawingFlags::empty(),
                    })],
                },
            }),
            pdu_source: SERVER_CHANNEL_ID,
            share_id,
        };
        server_sdi(io_channel_id, encode_vec(&sch).expect("encode demand active"))
    }

    /// A server Font Map PDU (share-data), the last PDU of connection finalization.
    fn font_map(io_channel_id: u16, share_id: u32) -> Vec<u8> {
        let sch = ShareControlHeader {
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: ShareDataPdu::FontMap(FontPdu::default()),
                stream_priority: StreamPriority::Medium,
                compression_flags: CompressionFlags::empty(),
                compression_type: CompressionType::K8,
            }),
            pdu_source: SERVER_CHANNEL_ID,
            share_id,
        };
        server_sdi(io_channel_id, encode_vec(&sch).expect("encode font map"))
    }

    /// An MCS Attach User Confirm (carries the user channel id), X.224-framed.
    fn attach_user_confirm(user_channel_id: u16) -> Vec<u8> {
        encode_vec(&X224(AttachUserConfirm {
            result: 0,
            initiator_id: user_channel_id,
        }))
        .expect("encode X224<AttachUserConfirm>")
    }

    /// HEADER PARSE: feed a constructed Attach User Confirm + Server Demand Active +
    /// Font Map to the parser and assert every extracted field, that the Font Map is
    /// recognized as the finalization boundary, and that the browser's compression
    /// choice flows into the built header.
    #[test]
    fn header_builder_extracts_from_activation_stream() {
        let (io, user, share_id, w, h) = (1003u16, 1007u16, 0x0102_0304u32, 1280u16, 1024u16);
        let mut hb = HeaderBuilder::default();

        assert!(!hb.observe(&attach_user_confirm(user)), "not the font map");
        assert_eq!(hb.user_channel_id, Some(user));

        assert!(!hb.observe(&demand_active(io, share_id, w, h)), "not the font map");
        assert_eq!(hb.share_id, Some(share_id));
        assert_eq!(hb.desktop, Some((w, h)));
        // io_channel_id falls back to the channel the Demand Active arrived on when
        // no Connect Response preceded it (the case exercised here).
        assert_eq!(hb.io_channel_id, Some(io));

        // The Font Map is recognized as the end of finalization.
        assert!(hb.observe(&font_map(io, share_id)), "font map ends finalization");

        // The header assembles with the browser's compression discriminant and the
        // (client-only) pointer flags defaulted to the browser connector's values.
        let header = hb
            .build(record_format::compression::RDP61)
            .expect("header complete");
        assert_eq!((header.width, header.height), (w, h));
        assert_eq!(header.share_id, share_id);
        assert_eq!(header.user_channel_id, user);
        assert_eq!(header.io_channel_id, io);
        assert_eq!(header.message_channel_id, None);
        assert_eq!(header.compression, record_format::compression::RDP61);
        assert!(!header.enable_server_pointer);
        assert!(!header.pointer_software_rendering);
    }

    /// An incomplete activation stream (never yields a Demand Active) cannot build a
    /// header — the recorder must fail closed rather than record with junk.
    #[test]
    fn header_builder_incomplete_yields_none() {
        let mut hb = HeaderBuilder::default();
        assert!(!hb.observe(&attach_user_confirm(1007)));
        assert!(hb.build(record_format::compression::NONE).is_none());
    }

    /// FAIL CLOSED: when the recorder rejects a frame (channel full/closed), the tee
    /// returns `RecordingFailed` and the frame is NEVER forwarded to the browser.
    #[tokio::test]
    async fn tee_fails_closed_without_forwarding() {
        // bound = 1, receiver retained → the first frame fills the single-slot
        // buffer, the next `try_frame` overflows (fail-closed trigger).
        let (handle, _rx) = RecorderHandle::for_test(1);
        handle
            .try_frame(0, record_format::ACTION_FASTPATH, b"fills-the-buffer".to_vec())
            .expect("first frame fits");

        let mut forwarded: Vec<u8> = Vec::new();
        let outcome = record_frame(
            &handle,
            &mut forwarded,
            10,
            record_format::ACTION_FASTPATH,
            b"this-frame-must-not-be-delivered",
        )
        .await;

        assert_eq!(outcome, Err(BridgeOutcome::RecordingFailed));
        assert!(
            forwarded.is_empty(),
            "a frame that cannot be recorded must not be forwarded",
        );
    }

    /// HAPPY TEE: an accepting recorder both records the frame and forwards it.
    #[tokio::test]
    async fn tee_forwards_when_recorded() {
        let (handle, mut rx) = RecorderHandle::for_test(4);
        let mut forwarded: Vec<u8> = Vec::new();
        let pdu = b"a-graphics-pdu";
        let outcome =
            record_frame(&handle, &mut forwarded, 5, record_format::ACTION_X224, pdu).await;

        assert_eq!(outcome, Ok(()));
        assert_eq!(forwarded, pdu, "the frame is forwarded verbatim");
        // The frame reached the recorder channel.
        assert!(rx.try_recv().is_ok(), "the frame was queued for recording");
    }

    /// Build a wire-encoded Client Info PDU (as the browser would send it) with
    /// blank credentials, exactly as the connector wraps it: `ClientInfoPdu` →
    /// MCS `SendDataRequest` user data → `X224`. `compression` toggles the bulk
    /// compression flag so the compression-capture path can be exercised.
    fn encode_browser_client_info(compression: bool) -> Vec<u8> {
        let mut flags = ClientInfoFlags::UNICODE;
        if compression {
            flags |= ClientInfoFlags::COMPRESSION;
        }
        let info = ClientInfoPdu {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::INFO_PKT,
            },
            client_info: ClientInfo {
                credentials: Credentials {
                    username: String::new(),
                    password: String::new(),
                    domain: None,
                },
                code_page: 0,
                flags,
                compression_type: CompressionType::Rdp61,
                alternate_shell: String::new(),
                work_dir: String::new(),
                extra_info: ExtendedClientInfo {
                    address_family: AddressFamily::INET,
                    address: String::new(),
                    dir: String::new(),
                    optional_data: ExtendedClientOptionalInfo::default(),
                },
            },
        };
        let user_data = encode_vec(&info).expect("encode ClientInfoPdu");
        let sdr = SendDataRequest {
            initiator_id: 1004,
            channel_id: 1003,
            user_data: Cow::Owned(user_data),
        };
        encode_vec(&X224(sdr)).expect("encode X224<SendDataRequest>")
    }

    /// The make-or-break path: a browser Client Info PDU is decoded, has the vault
    /// login + password injected with AUTOLOGON set, is re-encoded, and the
    /// re-encoded bytes decode back to the injected values.
    #[test]
    fn client_info_inject_round_trip() {
        let wire = encode_browser_client_info(false);

        // Sanity: find_size frames exactly this one PDU.
        let info = ironrdp_pdu::find_size(&wire)
            .expect("find_size ok")
            .expect("a full PDU");
        assert_eq!(info.length, wire.len(), "one framed PDU");

        let (rewritten, compression) =
            rewrite_client_info(&wire, "vault-user", "s3cr3t").expect("recognized as Client Info");
        assert_ne!(rewritten, wire, "bytes changed after injection");
        // No COMPRESSION flag was set on the client info → no bulk compression.
        assert_eq!(compression, record_format::compression::NONE);

        // Decode the rewritten PDU back and assert the injection took.
        let X224(sdr) = decode::<X224<SendDataRequest>>(&rewritten).expect("decode rewritten");
        let decoded = decode::<ClientInfoPdu>(&sdr.user_data[..]).expect("decode ClientInfo");
        assert_eq!(decoded.client_info.credentials.username, "vault-user");
        assert_eq!(decoded.client_info.credentials.password, "s3cr3t");
        assert_eq!(decoded.client_info.credentials.domain, None);
        assert!(
            decoded
                .client_info
                .flags
                .contains(ClientInfoFlags::AUTOLOGON),
            "AUTOLOGON must be set so the injected password is used at logon",
        );
        assert!(
            decoded.client_info.flags.contains(ClientInfoFlags::UNICODE),
            "pre-existing flags must be preserved",
        );
    }

    /// The compression discriminant is captured only when the browser advertised
    /// bulk compression (the `COMPRESSION` flag), matching the connector's gating.
    #[test]
    fn client_info_compression_gated_on_flag() {
        let (_, comp_off) =
            rewrite_client_info(&encode_browser_client_info(false), "u", "p").unwrap();
        assert_eq!(comp_off, record_format::compression::NONE);

        let (_, comp_on) =
            rewrite_client_info(&encode_browser_client_info(true), "u", "p").unwrap();
        assert_eq!(comp_on, record_format::compression::RDP61);
    }

    /// A non-Client-Info PDU (a bare X.224 data PDU) is NOT recognized as a Client
    /// Info PDU, so the injector passes it through untouched.
    #[test]
    fn non_client_info_pdu_is_passed_through() {
        // An MCS SendDataRequest whose user data is not a ClientInfoPdu.
        let sdr = SendDataRequest {
            initiator_id: 1004,
            channel_id: 1003,
            user_data: Cow::Owned(vec![0xde, 0xad, 0xbe, 0xef]),
        };
        let wire = encode_vec(&X224(sdr)).expect("encode");
        assert!(rewrite_client_info(&wire, "u", "p").is_none());
    }

    /// An RDCleanPath request round-trips through `detect` + `from_der`, and the
    /// reader recovers the embedded X.224 connection PDU. Locks the request-parse
    /// contract the bridge depends on.
    #[tokio::test]
    async fn cleanpath_request_detect_and_read() {
        // Build a request the way the browser (iron-remote-desktop) would.
        let x224_cr = vec![0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0]; // arbitrary CR-ish bytes
        let request = RDCleanPathPdu {
            x224_connection_pdu: Some(
                ironrdp_rdcleanpath::der::asn1::OctetString::new(x224_cr.clone()).unwrap(),
            ),
            destination: Some("attacker-chosen:3389".to_string()),
            ..Default::default()
        };
        let der = request.to_der().expect("encode request");

        // detect frames the whole PDU.
        match RDCleanPathPdu::detect(&der) {
            DetectionResult::Detected { total_length, .. } => {
                assert_eq!(total_length, der.len())
            }
            other => panic!("expected Detected, got {other:?}"),
        }

        // The reader recovers the request (and its X.224 CR), plus no leftover.
        let mut cursor = std::io::Cursor::new(der);
        let (parsed, leftover) = read_cleanpath_request(&mut cursor)
            .await
            .expect("read request");
        assert!(leftover.is_empty());
        assert_eq!(parsed.x224_connection_pdu.unwrap().into_bytes(), x224_cr);
        // The destination is present but the bridge deliberately ignores it.
        assert_eq!(parsed.destination.as_deref(), Some("attacker-chosen:3389"));
    }
}
