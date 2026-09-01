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
//!    copies EXCEPT a one-shot Client Info injection on the browser→target path:
//!    the first `SendDataRequest` carrying a `ClientInfoPdu` has its credentials
//!    replaced with the login + vault password and `AUTOLOGON` set, then that
//!    direction switches to raw pass-through.

use std::sync::Arc;

use anyhow::Context;
use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::mcs::SendDataRequest;
use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPathPdu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::record::{PartUploader, RecordStatus, RecorderConfig, RecordingReport};

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
    /// A required recording could not keep up: fail closed. Retained for the
    /// deferred recording tee (see TODO(5.4)); not produced today.
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
/// the multipart upload was already opened caller-side.
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

/// The disposition of a finished [`run`]: the end outcome, the (deferred)
/// recording report, and the session's start timestamp (unix ms). The caller maps
/// this to the `SessionEnded` proto, stamping the end timestamp.
pub struct RunReport {
    pub outcome: BridgeOutcome,
    pub recording: Option<RecordingReport>,
    pub started_at_unix_ms: i64,
}

/// Run the RDCleanPath bridge over an already-authenticated mesh stream (the
/// gateway has read the CONNECT preamble, answered `200`, and now relays a raw
/// byte stream). Does the TCP+X.224+TLS hop to `target_address`, hands the browser
/// the target's X.224 CC + cert chain, then relays plaintext RDP with a one-shot
/// Client Info credential injection browser→target.
///
/// `uploader` is opened by the CALLER before dialing (so a session that cannot be
/// recorded is refused before the target is ever contacted). Recording itself is
/// DEFERRED (see TODO(5.4)): the tee is not wired, so any opened upload is aborted
/// here — only the fail-closed-before-dial gate is preserved.
#[allow(clippy::too_many_arguments)]
pub async fn run<S>(
    target_address: &str,
    target_server_ca: &str,
    login: &str,
    password: &Zeroizing<String>,
    cancel: Arc<Notify>,
    stream: S,
    uploader: Option<Box<dyn PartUploader>>,
    _rec_cfg: RecorderConfig,
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

    // target → browser: raw byte copy.
    // TODO(5.4): re-add the rdp-graphics-v1 tee here by parsing PDUs off this path
    // (instead of a raw copy) and feeding them to a spawned recorder before forwarding.
    let to_browser = async {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) | Err(_) => return BridgeOutcome::Closed,
                Ok(n) => {
                    if mesh_writer.write_all(&buf[..n]).await.is_err()
                        || mesh_writer.flush().await.is_err()
                    {
                        return BridgeOutcome::Closed;
                    }
                }
            }
        }
    };

    // browser → target: one-shot Client Info injection, then raw pass-through.
    let to_target = inject_then_relay(
        &mut mesh_reader,
        &mut target_write,
        login,
        password,
        leftover,
    );

    tokio::pin!(to_browser, to_target);
    let outcome = tokio::select! {
        _ = cancel.notified() => BridgeOutcome::Terminated,
        o = &mut to_browser => o,
        o = &mut to_target => o,
    };
    tracing::debug!(?outcome, "RDP relay finished");

    // Recording is deferred: abort any opened upload (nothing was teed into it).
    let recording = match uploader {
        Some(u) => {
            u.abort().await;
            Some(failed_report())
        }
        None => None,
    };

    RunReport {
        outcome,
        recording,
        started_at_unix_ms,
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
/// credentials + `AUTOLOGON`, forward it, then switch to raw pass-through for the
/// rest of the session. Everything before the Client Info PDU (the MCS connect
/// sequence) passes through unchanged; if the stream can't be framed, it degrades
/// to raw pass-through rather than wedging the session.
async fn inject_then_relay<R, W>(
    mesh_reader: &mut R,
    target_write: &mut W,
    login: &str,
    password: &str,
    mut buf: Vec<u8>,
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
                if let Some(rewritten) = rewrite_client_info(&buf[..info.length], login, password) {
                    // Found + injected the Client Info PDU. Forward it, then any
                    // already-buffered bytes, then raw-pump the rest.
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
/// post-injection browser→target tail and (implicitly) the target→browser path.
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
/// `AUTOLOGON`, and re-encode the whole X.224/MCS/ClientInfo stack. Returns `None`
/// when `pdu` is not a Client Info PDU (any other PDU passes through untouched).
///
/// Mirrors the connector's `create_client_info_pdu` wrapping (ironrdp-connector
/// `connection.rs`): `encode_send_data_request` wraps the `ClientInfoPdu` as the
/// user data of an MCS `SendDataRequest`, itself wrapped in `X224`.
fn rewrite_client_info(pdu: &[u8], login: &str, password: &str) -> Option<Vec<u8>> {
    let X224(mut sdr) = decode::<X224<SendDataRequest>>(pdu).ok()?;
    let mut info = decode::<ClientInfoPdu>(&sdr.user_data[..]).ok()?;

    info.client_info.credentials.username = login.to_string();
    info.client_info.credentials.password = password.to_string();
    info.client_info.credentials.domain = None;
    info.client_info.flags |= ClientInfoFlags::AUTOLOGON;

    let new_user_data = encode_vec(&info).ok()?;
    sdr.user_data = std::borrow::Cow::Owned(new_user_data);
    encode_vec(&X224(sdr)).ok()
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
    use ironrdp_pdu::rdp::client_info::{
        AddressFamily, ClientInfo, ClientInfoFlags, CompressionType, Credentials,
        ExtendedClientInfo, ExtendedClientOptionalInfo,
    };
    use ironrdp_pdu::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
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

    /// Build a wire-encoded Client Info PDU (as the browser would send it) with
    /// blank credentials, exactly as the connector wraps it: `ClientInfoPdu` →
    /// MCS `SendDataRequest` user data → `X224`.
    fn encode_browser_client_info() -> Vec<u8> {
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
                flags: ClientInfoFlags::UNICODE,
                compression_type: CompressionType::K8,
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
        let wire = encode_browser_client_info();

        // Sanity: find_size frames exactly this one PDU.
        let info = ironrdp_pdu::find_size(&wire)
            .expect("find_size ok")
            .expect("a full PDU");
        assert_eq!(info.length, wire.len(), "one framed PDU");

        let rewritten =
            rewrite_client_info(&wire, "vault-user", "s3cr3t").expect("recognized as Client Info");
        assert_ne!(rewritten, wire, "bytes changed after injection");

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
