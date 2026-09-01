//! The IronRDP bridge: the worker performs the full RDP handshake with the
//! injected password (so credentials never reach the browser), then becomes a
//! dumb byte relay between the browser (framed opcode stream over the mesh) and
//! the target RDP socket.
//!
//! Handshake: TCP → `connect_begin` (X.224) → TLS upgrade (tokio-rustls; verify
//! against the asset CA when pinned, else accept-any) → `mark_as_upgraded` →
//! `connect_finalize` (CredSSP disabled for the xrdp bring-up) → `ConnectionResult`.
//! Then: send the browser the seed HEADER (negotiated params) and relay
//! `(action, payload)` PDUs; the browser runs `ironrdp-session::ActiveStage` to
//! render and emits input bytes back. This is the architecture the P0 PoC proved.
//!
//! Ported from the PoC `capture.rs` blocking flow to async (`ironrdp-tokio`).

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use ironrdp_connector::{
    ClientConnector, Config, ConnectionResult, Credentials, DesktopSize, ServerName,
};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp_pdu::Action;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{
    connect_begin, connect_finalize, mark_as_upgraded, split_tokio_framed, FramedWrite, TokioFramed,
};

use crate::frame::{self, OP_HEADER, OP_INPUT, OP_PDU};
use crate::record_format::{self, Header};

/// How a [`run`] session ended, mapped to the `SessionEnded` reason string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The control plane signalled a teardown.
    Terminated,
    /// Either side closed naturally (browser WS close / target EOF).
    Closed,
    /// The target handshake failed (already surfaced to the browser as ERROR).
    ConnectFailed,
}

impl BridgeOutcome {
    pub fn reason(self) -> &'static str {
        match self {
            BridgeOutcome::Terminated => "terminated",
            BridgeOutcome::Closed => "closed",
            BridgeOutcome::ConnectFailed => "target_unavailable",
        }
    }
}

/// Run the RDP bridge over an already-authenticated mesh stream (the gateway has
/// read the CONNECT preamble and answered `200`; it now relays the framed opcode
/// protocol). Connects to the target, seeds the browser with the HEADER, then
/// pumps PDUs/input until either side closes or `cancel` fires.
pub async fn run<S>(
    target_address: &str,
    target_server_ca: &str,
    login: &str,
    password: &Zeroizing<String>,
    cancel: Arc<Notify>,
    stream: S,
) -> BridgeOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(stream);

    let (host, port) = match split_host_port(target_address) {
        Some(v) => v,
        None => {
            tracing::warn!(%target_address, "malformed RDP target address");
            frame::send_error(&mut mesh_writer, "malformed target address").await;
            return BridgeOutcome::ConnectFailed;
        }
    };

    let config = build_config(login.to_string(), password.to_string());

    let (result, target_framed) = match connect(config, &host, port, target_server_ca).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(%target_address, error = %e, "RDP target handshake failed");
            frame::send_error(&mut mesh_writer, "target connection failed").await;
            return BridgeOutcome::ConnectFailed;
        }
    };
    tracing::info!(
        %target_address,
        width = result.desktop_size.width,
        height = result.desktop_size.height,
        "RDP target connected; seeding browser",
    );

    // Seed HEADER frame (once, first): the negotiated params the browser needs to
    // build its ActiveStage.
    let header = header_from(&result);
    let mut header_bytes = Vec::new();
    if header.write(&mut header_bytes).is_err() {
        frame::send_error(&mut mesh_writer, "failed to encode session header").await;
        return BridgeOutcome::ConnectFailed;
    }
    if frame::write_frame(&mut mesh_writer, OP_HEADER, &header_bytes)
        .await
        .is_err()
        || mesh_writer.flush().await.is_err()
    {
        return BridgeOutcome::Closed;
    }

    // Raw two-direction pump.
    // ponytail: raw two-direction pump; genuinely raw (unlike ssh's channel bridge).
    let (mut target_read, mut target_write) = split_tokio_framed(target_framed);

    let outcome;
    loop {
        tokio::select! {
            _ = cancel.notified() => { outcome = BridgeOutcome::Terminated; break; }

            // target → browser: one RDP PDU → [0x01 PDU][action:u8][pdu bytes].
            pdu = target_read.read_pdu() => {
                match pdu {
                    Ok((action, payload)) => {
                        let mut out = Vec::with_capacity(payload.len() + 1);
                        out.push(action_u8(action));
                        out.extend_from_slice(&payload);
                        if frame::write_frame(&mut mesh_writer, OP_PDU, &out).await.is_err()
                            || mesh_writer.flush().await.is_err()
                        {
                            outcome = BridgeOutcome::Closed;
                            break;
                        }
                    }
                    // EOF / decode error on the target socket: natural close.
                    Err(_) => { outcome = BridgeOutcome::Closed; break; }
                }
            }

            // browser → target: INPUT bytes written raw to the target socket
            // (the browser's already-wire-formatted ActiveStage output).
            inbound = frame::read_frame(&mut mesh_reader) => {
                match inbound {
                    Ok((OP_INPUT, payload)) => {
                        if target_write.write_all(&payload).await.is_err() {
                            outcome = BridgeOutcome::Closed;
                            break;
                        }
                    }
                    // Any other opcode from the browser is unexpected; log + ignore.
                    Ok((op, _)) => tracing::debug!(opcode = op, "ignoring unexpected inbound opcode"),
                    // EOF / read error: the browser closed the WS. Natural close.
                    Err(_) => { outcome = BridgeOutcome::Closed; break; }
                }
            }
        }
    }

    tracing::debug!(?outcome, "RDP pump finished");
    outcome
}

/// Build the IronRDP connector config. Exactly the 30 fields published
/// `connector::Config` (0.10) exposes. `autologon: true` so the injected
/// password is actually used for logon.
fn build_config(username: String, password: String) -> Config {
    Config {
        desktop_size: DesktopSize {
            width: 1280,
            height: 1024,
        },
        desktop_scale_factor: 0,
        enable_tls: true,
        // ponytail: credssp=false for xrdp bring-up; per-asset knob when a Windows/NLA target lands.
        enable_credssp: false,
        credentials: Credentials::UsernamePassword { username, password },
        domain: None,
        client_build: 0,
        client_name: "jumpgate-rdp-proxy".to_owned(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: platform(),
        hardware_id: None,
        request_data: None,
        // The injected password is only consumed at logon when autologon is set.
        autologon: true,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: Some(CompressionType::Rdp61),
        // No user-visible pointer/cursor state is rendered worker-side (the
        // browser's ActiveStage owns that); mirror the proven PoC settings.
        enable_server_pointer: false,
        pointer_software_rendering: true,
        multitransport_flags: None,
    }
}

fn platform() -> MajorPlatformType {
    #[cfg(target_os = "windows")]
    {
        MajorPlatformType::WINDOWS
    }
    #[cfg(target_os = "macos")]
    {
        MajorPlatformType::MACINTOSH
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        MajorPlatformType::UNIX
    }
}

/// Async port of the PoC `connect()`: TCP → connect_begin → TLS upgrade →
/// mark_as_upgraded → connect_finalize.
async fn connect(
    config: Config,
    host: &str,
    port: u16,
    target_server_ca: &str,
) -> anyhow::Result<(ConnectionResult, TokioFramed<TlsStream<TcpStream>>)> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("TCP connect to RDP target {host}:{port}"))?;
    let client_addr = tcp.local_addr().context("target socket local addr")?;

    let mut framed: TokioFramed<TcpStream> = TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config, client_addr);

    let should_upgrade = connect_begin(&mut framed, &mut connector)
        .await
        .context("RDP connect_begin")?;

    // The X.224 connection-confirm is fully consumed by connect_begin, so there
    // is no leftover before the TLS ClientHello.
    let initial = framed.into_inner_no_leftover();
    let (tls_stream, server_public_key) = tls_upgrade(initial, host, target_server_ca)
        .await
        .context("target TLS upgrade")?;

    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed: TokioFramed<TlsStream<TcpStream>> = TokioFramed::new(tls_stream);

    let mut network_client = ReqwestNetworkClient::new();
    let result = connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        ServerName::new(host),
        server_public_key,
        // No Kerberos: enable_credssp is false for the xrdp bring-up.
        None,
    )
    .await
    .context("RDP connect_finalize")?;

    Ok((result, upgraded_framed))
}

/// Upgrade the target TCP stream to TLS. When `target_server_ca` is non-empty the
/// server cert is verified against it (fail closed / MITM protection); empty =
/// accept any (TOFU-off, the xrdp bring-up path). Returns the TLS stream and the
/// server's public key (required by `connect_finalize` for CredSSP).
async fn tls_upgrade(
    stream: TcpStream,
    server_name: &str,
    target_server_ca: &str,
) -> anyhow::Result<(TlsStream<TcpStream>, Vec<u8>)> {
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
    // CredSSP does not support TLS resumption; disable it (harmless when off too).
    config.resumption = rustls::client::Resumption::disabled();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let dns = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .with_context(|| format!("invalid TLS server name {server_name}"))?;
    let tls_stream = connector
        .connect(dns, stream)
        .await
        .context("TLS handshake with target")?;

    let server_public_key = {
        let (_io, conn) = tls_stream.get_ref();
        let cert = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .context("target presented no TLS certificate")?;
        extract_tls_server_public_key(cert.as_ref())?
    };

    Ok((tls_stream, server_public_key))
}

/// Extract the DER-encoded SubjectPublicKey BIT STRING from the server leaf cert.
fn extract_tls_server_public_key(cert: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert).context("parse target TLS certificate")?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not byte-aligned")?
        .to_owned();
    Ok(key)
}

/// Map a decoded `ConnectionResult` to the `rdp-graphics-v1` seed [`Header`] —
/// the exact field mapping from the PoC `active_stage()`.
fn header_from(r: &ConnectionResult) -> Header {
    use record_format::compression;
    Header {
        width: r.desktop_size.width,
        height: r.desktop_size.height,
        user_channel_id: r.user_channel_id,
        io_channel_id: r.io_channel_id,
        message_channel_id: r.message_channel_id,
        share_id: r.share_id,
        compression: match r.compression_type {
            None => compression::NONE,
            Some(CompressionType::K8) => compression::K8,
            Some(CompressionType::K64) => compression::K64,
            Some(CompressionType::Rdp6) => compression::RDP6,
            Some(CompressionType::Rdp61) => compression::RDP61,
        },
        enable_server_pointer: r.enable_server_pointer,
        pointer_software_rendering: r.pointer_software_rendering,
    }
}

fn action_u8(a: Action) -> u8 {
    match a {
        Action::FastPath => record_format::ACTION_FASTPATH,
        Action::X224 => record_format::ACTION_X224,
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

/// Accept-any TLS verifier for the unpinned target path — ported verbatim from
/// the PoC. Only reachable when the asset configures no `target_server_ca`.
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
    fn build_config_uses_autologon_and_no_credssp() {
        let cfg = build_config("admin".into(), "pw".into());
        assert!(cfg.autologon, "injected password requires autologon");
        assert!(!cfg.enable_credssp, "xrdp bring-up is TLS-only");
        assert!(cfg.enable_tls);
        match cfg.credentials {
            Credentials::UsernamePassword { username, .. } => assert_eq!(username, "admin"),
            _ => panic!("expected username/password credentials"),
        }
    }

    /// LIVE decode test (requires a real xrdp target — NOT available in CI, so
    /// `#[ignore]`d). Run manually:
    ///
    /// ```text
    /// docker run --rm -p 3389:3389 danielguerra/ubuntu-xrdp:20.04
    /// cargo test -p rdp-proxy --lib -- --ignored bridge::tests::live_connect_seeds_header
    /// ```
    ///
    /// Connects, finalizes, and asserts the negotiated `ConnectionResult` maps to
    /// a non-degenerate seed HEADER (the same handshake `run` performs).
    #[tokio::test]
    #[ignore = "requires a live danielguerra/ubuntu-xrdp:20.04 on 127.0.0.1:3389"]
    async fn live_connect_seeds_header() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = build_config("admin".into(), "password".into());
        let (result, _framed) = connect(config, "127.0.0.1", 3389, "")
            .await
            .expect("connect to live xrdp");
        let header = header_from(&result);
        assert!(header.width > 0 && header.height > 0, "non-degenerate size");
        let mut buf = Vec::new();
        header.write(&mut buf).expect("encode header");
        assert_eq!(&buf[..4], record_format::MAGIC, "header carries the RDPG magic");
    }
}
