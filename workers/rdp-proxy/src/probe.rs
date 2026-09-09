//! Credential-free RDP TLS host-identity probe + per-session runtime match.
//!
//! [`observe`] speaks just enough of the RDP wire to reach and capture the
//! target's TLS identity: it TCP-connects, sends an X.224 Connection Request
//! negotiating TLS (`SecurityProtocol::SSL`), reads the target's X.224 Connection
//! Confirm, completes a TLS handshake capturing the presented certificate chain,
//! and then STOPS — no MCS connect sequence, no Client Info PDU, no credential is
//! ever sent. It reuses the SAME X.224 + rustls path a live session takes ([`crate::bridge`]),
//! stopping the instant the TLS identity is available. This is the same observation
//! used for onboarding evidence and for per-session verification.
//!
//! [`match_identity`] is the runtime enforcement half: it checks an observed chain
//! against the trust anchors `PrepareSession` returned BEFORE any credential is
//! released — exact leaf-fingerprint equality for a `tls_leaf` pin, or full X.509
//! chain-to-CA validation plus the configured DNS/IP name (and the anchor's own CA
//! present in the verified chain) for a `tls_ca` anchor. No match → fail closed.
//!
//! The capture handshake accepts any certificate at the *trust* layer (identity is
//! enforced by [`match_identity`], not by `crypto/tls`) but STILL verifies the
//! server's handshake signature — proof it holds the presented leaf's private key —
//! by delegating the signature checks to a real webpki verifier. That proof-of-
//! possession is what makes fingerprint pinning sound: an attacker cannot replay a
//! victim's (public) certificate without its key. This replaces the old accept-any
//! `NoCertificateVerification`, which blindly asserted signatures too.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use ironrdp_core::encode_vec;
use ironrdp_pdu::nego::{ConnectionRequest, RequestFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, IpAddr, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    probe_assignment, probe_result, ProbeAssignment, ProbeEvidence, ProbeEvidenceKind,
    ProbeFailureCategory, ProbeLimits, ProbeOutcome, ProbeResult, ProbeTlsMetadata,
};

/// The ring crypto provider, shared by the capture handshake and the per-anchor CA
/// verifier so neither depends on a process-wide default being installed (the
/// integration tests do not run `main`).
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What a credential-free probe saw at the target: the presented TLS chain (leaf
/// first, DER) and session metadata. No MCS/Client Info was ever sent.
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    pub chain: Vec<CertificateDer<'static>>,
    /// Canonical `SHA256:<base64>` over the leaf DER.
    pub leaf_fingerprint: String,
    /// Distinct bare IPs the endpoint resolved to (no port). Warden validates
    /// each with `net.ParseIP`, which requires a bare IP.
    pub resolved_addresses: Vec<String>,
    pub tls_version: String,
    pub cipher_suite: String,
    pub server_name: String,
    pub connect_ms: i64,
    pub handshake_ms: i64,
}

/// A terminal probe failure, categorized for the [`ProbeResult`] it maps to.
#[derive(Debug, thiserror::Error)]
pub enum ProbeFailure {
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("connection refused: {0}")]
    ConnectionRefused(String),
    #[error("connection timed out: {0}")]
    ConnectionTimeout(String),
    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),
    #[error("insecure downgrade: {0}")]
    InsecureDowngrade(String),
    #[error("identity too large: {0}")]
    IdentityTooLarge(String),
    #[error("malformed assignment: {0}")]
    MalformedIdentity(String),
}

impl ProbeFailure {
    fn category(&self) -> ProbeFailureCategory {
        match self {
            ProbeFailure::DnsResolutionFailed(_) => ProbeFailureCategory::DnsResolutionFailed,
            ProbeFailure::ConnectionRefused(_) => ProbeFailureCategory::ConnectionRefused,
            ProbeFailure::ConnectionTimeout(_) => ProbeFailureCategory::ConnectionTimeout,
            ProbeFailure::ProtocolMismatch(_) => ProbeFailureCategory::ProtocolMismatch,
            ProbeFailure::InsecureDowngrade(_) => ProbeFailureCategory::InsecureDowngrade,
            ProbeFailure::IdentityTooLarge(_) => ProbeFailureCategory::IdentityTooLarge,
            ProbeFailure::MalformedIdentity(_) => ProbeFailureCategory::MalformedIdentity,
        }
    }
}

/// The worker-side view of a `PrepareSession` trust anchor: the public identity
/// constraint an operator approved. `tls_leaf` carries the exact leaf fingerprint;
/// `tls_ca` carries the CA fingerprint plus the required DNS/IP name.
#[derive(Debug, Clone)]
pub struct SessionAnchor {
    pub id: String,
    pub kind: String,
    pub fingerprint: String,
    pub required_dns_names: Vec<String>,
    pub required_ip_addresses: Vec<String>,
    /// The anchor's own approved CA cert PEM (`tls_ca`). The worker builds its
    /// `RootCertStore` from exactly this, binding chain validation to the approved
    /// anchor rather than a mutable config column. Empty for `tls_leaf` (an exact
    /// fingerprint pin needs no CA material); an empty `tls_ca` fails closed.
    pub public_material: String,
}

/// The anchor the worker matched, threaded into `IssueSessionCredential`.
#[derive(Debug, Clone)]
pub struct AnchorMatch {
    pub anchor_id: String,
    pub observed_fingerprint: String,
}

/// Why the observed target identity did not resolve to an approved anchor. Fails
/// closed; the caller maps it to a stable, client-safe reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// No approved anchor matched the observed chain — an unknown target, a changed
    /// identity, an expired/wrong-name leaf, or no anchors at all. The MITM signal.
    Unmatched,
}

/// Canonical SHA-256 fingerprint of DER bytes, in the exact form warden and the
/// pg-proxy worker use (`"SHA256:" + raw-std-base64`), so an observed fingerprint
/// compares equal to the anchor warden stored.
pub fn fingerprint_der(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(der);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sum)
    )
}

/// Enforce the observed target chain against the approved anchors before a
/// credential is released. Returns the matched anchor id + observed leaf
/// fingerprint (to report to warden), or [`IdentityError::Unmatched`].
///
/// - `tls_leaf`: exact leaf-fingerprint equality (a pin; name/validity not
///   re-checked, matching warden's exact-equality session rule).
/// - `tls_ca`: the leaf must chain to the anchor's own approved CA material (validity
///   enforced via `now`), the configured DNS/IP name must match the leaf, AND the
///   anchor's own CA cert must be the trust root of that verified chain — binding the
///   match to the approved anchor material, not to any mutable config column.
pub fn match_identity(
    chain: &[CertificateDer<'_>],
    anchors: &[SessionAnchor],
    now: UnixTime,
) -> Result<AnchorMatch, IdentityError> {
    let leaf = chain.first().ok_or(IdentityError::Unmatched)?;
    let leaf_fp = fingerprint_der(leaf);
    for a in anchors {
        let matched = match a.kind.as_str() {
            "tls_leaf" => a.fingerprint == leaf_fp,
            "tls_ca" => match_ca_anchor(chain, a, now),
            _ => false,
        };
        if matched {
            return Ok(AnchorMatch {
                anchor_id: a.id.clone(),
                observed_fingerprint: leaf_fp,
            });
        }
    }
    Err(IdentityError::Unmatched)
}

/// Whether the observed leaf chains to the CA anchor `a`: a valid X.509 chain whose
/// trust root is exactly the anchor's own approved CA cert (its `public_material`,
/// selected by fingerprint), with the required DNS/IP name satisfied by the leaf.
/// Uses rustls' own webpki verifier for chain-to-root + name + validity in one call.
/// The trust root is warden-authoritative anchor material, never a config column.
fn match_ca_anchor(chain: &[CertificateDer<'_>], a: &SessionAnchor, now: UnixTime) -> bool {
    if a.public_material.trim().is_empty() {
        return false; // a CA anchor with no approved CA material can never be validated
    }
    // A CA anchor MUST carry a name; an empty constraint never matches (a bare CA
    // must not authorize an arbitrary leaf).
    if a.required_dns_names.is_empty() && a.required_ip_addresses.is_empty() {
        return false;
    }
    // Trust root = only the cert(s) in the anchor's own material whose fingerprint is
    // the anchor's. This binds the match to the approved anchor, not to any CA in a
    // shared bundle.
    let mut roots = RootCertStore::empty();
    let mut any_root = false;
    let mut pem = a.public_material.as_bytes();
    for cert in rustls_pemfile::certs(&mut pem).flatten() {
        if fingerprint_der(&cert) == a.fingerprint && roots.add(cert).is_ok() {
            any_root = true;
        }
    }
    if !any_root {
        return false;
    }
    let verifier = match WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Some((leaf, intermediates)) = chain.split_first() else {
        return false;
    };
    // verify_server_cert does chain-to-root + validity + the given name in one call.
    // Every configured name must be satisfied by the same leaf/chain.
    for name in &a.required_dns_names {
        let Ok(sn) = ServerName::try_from(name.clone()) else {
            return false;
        };
        if verifier
            .verify_server_cert(leaf, intermediates, &sn, &[], now)
            .is_err()
        {
            return false;
        }
    }
    for ip in &a.required_ip_addresses {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        let sn = ServerName::IpAddress(IpAddr::from(addr));
        if verifier
            .verify_server_cert(leaf, intermediates, &sn, &[], now)
            .is_err()
        {
            return false;
        }
    }
    true
}

/// A `rustls::ClientConfig` for the credential-free capture handshake, shared by the
/// probe and the live [`crate::bridge`] hop. It accepts any certificate at the trust
/// layer (identity is enforced afterward by [`match_identity`]) but verifies the
/// server's handshake signature (proof of possession), so a captured leaf
/// fingerprint is a sound pin. RDP does not use TLS resumption; it is disabled.
pub fn capture_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaptureVerifier::new()))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config
}

/// Accept-any-at-trust, verify-signature TLS verifier for the capture handshake.
/// The trust decision is deferred to [`match_identity`] on the captured chain; the
/// signature checks (proof the peer holds the leaf's key) are delegated to a real
/// webpki verifier so pinning is not spoofable.
#[derive(Debug)]
struct CaptureVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl CaptureVerifier {
    fn new() -> Self {
        // The root set is irrelevant to signature verification (the only thing we
        // delegate); the public webpki roots are a convenient non-empty store.
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .expect("build webpki verifier for signature delegation");
        Self { inner }
    }
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Trust is enforced by match_identity on the captured chain, not here.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Distinct bare IPs (no port) from resolved socket addresses, order preserved.
/// Warden's `validateResult` runs `net.ParseIP` on each, which rejects `ip:port`.
fn distinct_ips(addrs: &[SocketAddr]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(addrs.len());
    for a in addrs {
        let ip = a.ip().to_string();
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Clamp a non-positive millisecond bound to 1ms so a misconfigured limit never
/// yields a zero (immediate) or negative timeout.
fn ms(millis: i64) -> Duration {
    Duration::from_millis(millis.max(1) as u64)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Run the probe described by `assignment` and map the outcome to a single terminal
/// [`ProbeResult`], honoring the assignment's total deadline. Always returns exactly
/// one result (Succeeded with chain evidence, or Failed with a category + detail).
pub async fn run_to_result(assignment: ProbeAssignment) -> ProbeResult {
    let total_ms = assignment
        .limits
        .as_ref()
        .map(|l| l.total_timeout_ms)
        .unwrap_or(0);
    let outcome = if total_ms > 0 {
        match timeout(Duration::from_millis(total_ms as u64), run(&assignment)).await {
            Ok(r) => r,
            Err(_) => Err(ProbeFailure::ConnectionTimeout(
                "total probe deadline exceeded".into(),
            )),
        }
    } else {
        run(&assignment).await
    };

    match outcome {
        Ok(obs) => {
            tracing::info!(
                fingerprint = %obs.leaf_fingerprint,
                tls = %obs.tls_version,
                connect_ms = obs.connect_ms,
                handshake_ms = obs.handshake_ms,
                "rdp target identity probe succeeded",
            );
            success_result(&assignment, obs)
        }
        Err(f) => {
            tracing::warn!(category = ?f.category(), detail = %f, "rdp target identity probe failed");
            failure_result(&assignment, f.category(), f.to_string())
        }
    }
}

/// Probe the RDP endpoint in `assignment` and return its observed TLS identity.
pub async fn run(assignment: &ProbeAssignment) -> Result<ProbeObservation, ProbeFailure> {
    let endpoint = match &assignment.endpoint {
        Some(probe_assignment::Endpoint::Rdp(e)) => e,
        _ => {
            return Err(ProbeFailure::MalformedIdentity(
                "assignment is not an RDP endpoint".into(),
            ))
        }
    };
    let limits = assignment.limits.as_ref().ok_or_else(|| {
        ProbeFailure::MalformedIdentity("assignment carries no probe limits".into())
    })?;
    let server_name = if endpoint.server_name.is_empty() {
        endpoint.host.as_str()
    } else {
        endpoint.server_name.as_str()
    };
    observe(&endpoint.host, endpoint.port as u16, server_name, limits).await
}

/// Connect to `host:port`, negotiate TLS over X.224, capture the presented chain,
/// and STOP before the MCS connect sequence. `server_name` sets SNI + the DNS name
/// checked in the handshake signature path. Never sends or receives a credential.
pub async fn observe(
    host: &str,
    port: u16,
    server_name: &str,
    limits: &ProbeLimits,
) -> Result<ProbeObservation, ProbeFailure> {
    // Resolve under the DNS deadline, recording the observed addresses.
    let addrs: Vec<SocketAddr> =
        match timeout(ms(limits.dns_timeout_ms), tokio::net::lookup_host((host, port))).await {
            Ok(Ok(iter)) => iter.collect(),
            Ok(Err(e)) => return Err(ProbeFailure::DnsResolutionFailed(e.to_string())),
            Err(_) => return Err(ProbeFailure::DnsResolutionFailed("DNS lookup timed out".into())),
        };
    if addrs.is_empty() {
        return Err(ProbeFailure::DnsResolutionFailed(format!(
            "{host}:{port} resolved to no addresses"
        )));
    }
    let resolved_addresses = distinct_ips(&addrs);

    // Connect (first address that answers) under the connect deadline.
    let connect_timeout = ms(limits.connect_timeout_ms);
    let connect_start = Instant::now();
    let tcp = connect_any(&addrs, connect_timeout).await?;
    let _ = tcp.set_nodelay(true);
    let connect_ms = connect_start.elapsed().as_millis() as i64;

    // X.224 negotiation + TLS handshake under the handshake deadline.
    let handshake_start = Instant::now();
    let obs = match timeout(
        ms(limits.handshake_timeout_ms),
        negotiate_and_capture(tcp, server_name, limits),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(ProbeFailure::ConnectionTimeout(
                "RDP TLS handshake did not complete before the deadline".into(),
            ))
        }
    };
    let handshake_ms = handshake_start.elapsed().as_millis() as i64;

    let (chain, tls_version, cipher_suite) = obs;
    let leaf = chain.first().ok_or_else(|| {
        ProbeFailure::MalformedIdentity("target presented no certificate".into())
    })?;
    let leaf_fingerprint = fingerprint_der(leaf);

    Ok(ProbeObservation {
        leaf_fingerprint,
        chain,
        resolved_addresses,
        tls_version,
        cipher_suite,
        server_name: server_name.to_string(),
        connect_ms,
        handshake_ms,
    })
}

/// Send the X.224 CR (negotiating TLS), read the CC, then TLS-upgrade capturing the
/// chain. Enforces the chain/certificate byte + count ceilings on the captured
/// chain. Returns (chain DER, TLS version, cipher suite).
async fn negotiate_and_capture(
    mut tcp: TcpStream,
    server_name: &str,
    limits: &ProbeLimits,
) -> Result<(Vec<CertificateDer<'static>>, String, String), ProbeFailure> {
    // X.224 Connection Request negotiating TLS security, exactly as a live client's
    // connector emits (the browser's CR the live bridge forwards).
    let cr = encode_vec(&X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .map_err(|e| ProbeFailure::ProtocolMismatch(format!("encode X.224 CR: {e}")))?;
    tcp.write_all(&cr)
        .await
        .map_err(|e| ProbeFailure::ProtocolMismatch(format!("write X.224 CR: {e}")))?;
    tcp.flush()
        .await
        .map_err(|e| ProbeFailure::ProtocolMismatch(format!("flush X.224 CR: {e}")))?;
    read_x224_confirm(&mut tcp).await?;

    // TLS upgrade with the shared capture config (accept-any-at-trust, verify sig).
    let connector = tokio_rustls::TlsConnector::from(Arc::new(capture_client_config()));
    let dns = ServerName::try_from(server_name.to_owned())
        .map_err(|_| ProbeFailure::ProtocolMismatch(format!("invalid TLS server name {server_name}")))?;
    let tls = connector
        .connect(dns, tcp)
        .await
        .map_err(|e| ProbeFailure::ProtocolMismatch(format!("TLS handshake with target: {e}")))?;

    let (_io, conn) = tls.get_ref();
    let chain: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
        .unwrap_or_default();
    if chain.is_empty() {
        return Err(ProbeFailure::MalformedIdentity(
            "target presented no certificate".into(),
        ));
    }
    if limits.max_chain_certificates > 0 && chain.len() > limits.max_chain_certificates as usize {
        return Err(ProbeFailure::IdentityTooLarge(format!(
            "chain of {} certificates exceeds the ceiling of {}",
            chain.len(),
            limits.max_chain_certificates
        )));
    }
    if limits.max_certificate_bytes > 0 {
        for c in &chain {
            if c.as_ref().len() > limits.max_certificate_bytes as usize {
                return Err(ProbeFailure::IdentityTooLarge(format!(
                    "certificate of {} bytes exceeds the ceiling of {}",
                    c.as_ref().len(),
                    limits.max_certificate_bytes
                )));
            }
        }
    }
    let version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_default();
    // STOP: the handshake is done and the chain captured. The MCS connect sequence
    // and Client Info PDU are never sent; the TLS stream is dropped here.
    Ok((chain, version, cipher))
}

/// Read one framed X.224 Connection Confirm, bounding the read. A negotiation
/// FAILURE (the target refused TLS) is a hard [`ProbeFailure::InsecureDowngrade`].
async fn read_x224_confirm(tcp: &mut TcpStream) -> Result<(), ProbeFailure> {
    use ironrdp_core::decode;
    use ironrdp_pdu::nego::ConnectionConfirm;

    const MAX_READ_SIZE: usize = 512;
    let mut buf = vec![0u8; 19];
    let mut filled = 0;
    loop {
        if let Some(info) = ironrdp_pdu::find_size(&buf[..filled])
            .map_err(|e| ProbeFailure::ProtocolMismatch(format!("frame X.224 CC: {e}")))?
        {
            if filled >= info.length {
                let pdu = &buf[..info.length];
                return match decode::<X224<ConnectionConfirm>>(pdu) {
                    Ok(X224(ConnectionConfirm::Response { .. })) => Ok(()),
                    Ok(X224(ConnectionConfirm::Failure { code })) => {
                        Err(ProbeFailure::InsecureDowngrade(format!(
                            "target refused the TLS negotiation (RDP_NEG_FAILURE {code})"
                        )))
                    }
                    Err(e) => Err(ProbeFailure::ProtocolMismatch(format!(
                        "decode X.224 Connection Confirm: {e}"
                    ))),
                };
            }
        }
        if filled == buf.len() {
            if buf.len() >= MAX_READ_SIZE {
                return Err(ProbeFailure::IdentityTooLarge(
                    "X.224 Connection Confirm exceeds bound".into(),
                ));
            }
            buf.resize(MAX_READ_SIZE, 0);
        }
        let n = tcp
            .read(&mut buf[filled..])
            .await
            .map_err(|e| ProbeFailure::ProtocolMismatch(format!("read X.224 CC: {e}")))?;
        if n == 0 {
            return Err(ProbeFailure::ProtocolMismatch(
                "EOF before a complete X.224 Connection Confirm".into(),
            ));
        }
        filled += n;
    }
}

async fn connect_any(addrs: &[SocketAddr], per_addr: Duration) -> Result<TcpStream, ProbeFailure> {
    let mut last: Option<ProbeFailure> = None;
    for addr in addrs {
        match timeout(per_addr, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(ProbeFailure::ConnectionRefused(e.to_string())),
            Err(_) => {
                last = Some(ProbeFailure::ConnectionTimeout(format!(
                    "TCP connect to {addr} timed out"
                )))
            }
        }
    }
    Err(last.unwrap_or_else(|| ProbeFailure::ConnectionRefused("no address answered".into())))
}

// --- Result / evidence mapping ----------------------------------------------

fn success_result(pa: &ProbeAssignment, obs: ProbeObservation) -> ProbeResult {
    let evidence = chain_evidence(&obs.chain);
    ProbeResult {
        job_id: pa.job_id.clone(),
        asset_id: pa.asset_id.clone(),
        endpoint_revision: pa.endpoint_revision,
        lease_token: pa.lease_token.clone(),
        protocol: pa.protocol,
        outcome: ProbeOutcome::Succeeded as i32,
        observed_at_unix_ms: now_unix_ms(),
        resolved_addresses: obs.resolved_addresses,
        evidence,
        failure_category: ProbeFailureCategory::Unspecified as i32,
        failure_detail: String::new(),
        protocol_metadata: Some(probe_result::ProtocolMetadata::Tls(ProbeTlsMetadata {
            version: obs.tls_version,
            cipher_suite: obs.cipher_suite,
            server_name: obs.server_name,
            alpn: String::new(),
        })),
    }
}

fn failure_result(pa: &ProbeAssignment, category: ProbeFailureCategory, detail: String) -> ProbeResult {
    ProbeResult {
        job_id: pa.job_id.clone(),
        asset_id: pa.asset_id.clone(),
        endpoint_revision: pa.endpoint_revision,
        lease_token: pa.lease_token.clone(),
        protocol: pa.protocol,
        outcome: ProbeOutcome::Failed as i32,
        observed_at_unix_ms: now_unix_ms(),
        resolved_addresses: Vec::new(),
        evidence: Vec::new(),
        failure_category: category as i32,
        failure_detail: detail,
        protocol_metadata: None,
    }
}

/// Render an observed TLS chain (leaf first) into [`ProbeEvidence`] rows, mirroring
/// the pg-proxy worker's `chainEvidence`: the leaf is `TLS_LEAF`, a trailing
/// self-signed CA is `TLS_PRESENTED_ROOT`, and the rest are `TLS_INTERMEDIATE`. The
/// X.509 fields are best-effort — a cert that will not parse still yields its
/// fingerprint + PEM (identity is never invented, only display detail is skipped).
fn chain_evidence(chain: &[CertificateDer<'_>]) -> Vec<ProbeEvidence> {
    let last = chain.len().saturating_sub(1);
    chain
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let der = cert.as_ref();
            let mut ev = ProbeEvidence {
                sha256_fingerprint: fingerprint_der(der),
                public_material: pem_encode(der),
                ..Default::default()
            };
            let self_signed = fill_cert_fields(der, &mut ev);
            ev.kind = if i == 0 {
                ProbeEvidenceKind::TlsLeaf as i32
            } else if i == last && self_signed {
                ProbeEvidenceKind::TlsPresentedRoot as i32
            } else {
                ProbeEvidenceKind::TlsIntermediate as i32
            };
            if i + 1 < chain.len() {
                ev.issuer_sha256_fingerprint = fingerprint_der(chain[i + 1].as_ref());
            }
            ev
        })
        .collect()
}

/// Parse `der` and fill the display fields of `ev`. Returns whether the certificate
/// is self-signed (subject == issuer), used to tag a presented root.
fn fill_cert_fields(der: &[u8], ev: &mut ProbeEvidence) -> bool {
    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return false;
    };
    ev.certificate_subject = cert.subject().to_string();
    ev.certificate_issuer = cert.issuer().to_string();
    ev.serial_number = cert.raw_serial_as_string();
    ev.algorithm = public_key_algorithm(&cert);
    ev.valid_from_unix_ms = cert.validity().not_before.timestamp() * 1000;
    ev.valid_until_unix_ms = cert.validity().not_after.timestamp() * 1000;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            match gn {
                GeneralName::DNSName(d) => ev.dns_names.push((*d).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_bytes(bytes) {
                        ev.ip_addresses.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    cert.subject() == cert.issuer()
}

fn public_key_algorithm(cert: &x509_parser::certificate::X509Certificate) -> String {
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(_)) => "RSA".into(),
        Ok(PublicKey::EC(_)) => "ECDSA".into(),
        Ok(PublicKey::DSA(_)) => "DSA".into(),
        Ok(PublicKey::GostR3410(_)) | Ok(PublicKey::GostR3410_2012(_)) => "GOST".into(),
        _ => "Unknown".into(),
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let a: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(a).to_string())
        }
        16 => {
            let a: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

/// PEM-encode a DER certificate (64-char base64 lines), matching Go's
/// `pem.EncodeToMemory` output the migration/backfill stores.
fn pem_encode(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}
