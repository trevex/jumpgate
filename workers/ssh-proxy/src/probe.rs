//! Credential-free SSH host-identity probe.
//!
//! Reaches SSH key exchange against a target and captures its host key, then
//! STOPS: no `SSH_MSG_USERAUTH_REQUEST` is ever sent. russh's
//! [`connect_stream`](russh::client::connect_stream) runs the transport
//! handshake (banner exchange + KEX + host-key check) and returns a handle
//! BEFORE any user-auth; we snapshot the host key inside `check_server_key`,
//! then drop the handle without calling any `authenticate_*`. The observation is
//! pure public identity material — host-key algorithm, SHA-256 fingerprint,
//! OpenSSH authorized_keys line — plus the server identification banner and
//! connection timings.
//!
//! The probe never releases or holds a credential: it observes identity, it does
//! not open a session. It therefore accepts whatever host key the target
//! presents (host-key *enforcement* is [`crate::target`]'s job on the real hop).
//!
//! ## Host certificates are deferred (russh-blocked)
//!
//! russh 0.62 has no host-certificate support: the client callback is
//! `check_server_key(&ssh_key::PublicKey)`, its `KexProgress::Done.server_host_key`
//! is `Option<PublicKey>` decoded via `KeyData::decode` (plain key data only,
//! never an `ssh_key::Certificate`), the default host-key algorithm set carries
//! no `*-cert-v01@openssh.com`, and the russh server serves only
//! `Vec<PrivateKey>`. Observing a host certificate's principals/validity would
//! require re-implementing KEX host-key negotiation and cert parsing, which we do
//! not do. The probe therefore emits only `SSH_HOST_KEY` evidence; the
//! `PROBE_EVIDENCE_KIND_SSH_HOST_CERTIFICATE` path is left for a russh version
//! that surfaces the certificate (see the ignored `host_certificate_evidence_deferred`
//! integration test).

use std::borrow::Cow;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use russh::keys::ssh_key::{self, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    probe_assignment, probe_result, ProbeAssignment, ProbeEvidence, ProbeEvidenceKind,
    ProbeFailureCategory, ProbeLimits, ProbeOutcome, ProbeResult, ProbeSshMetadata,
};

/// What the probe observed about a target's SSH host identity. Public material
/// only — no secret, credential, or login is involved in a probe.
#[derive(Debug, Clone)]
pub struct ProbeObservation {
    /// Host-key algorithm, OpenSSH form (e.g. `ssh-ed25519`).
    pub algorithm: String,
    /// `SHA256:...` fingerprint of the presented host key.
    pub sha256_fingerprint: String,
    /// OpenSSH authorized_keys line for the presented host key.
    pub openssh_public_line: String,
    /// The server identification banner (`SSH-2.0-...`).
    pub banner: String,
    /// Addresses the endpoint resolved to (`ip:port`).
    pub resolved_addresses: Vec<String>,
    /// Milliseconds to establish the TCP connection.
    pub connect_ms: i64,
    /// Milliseconds for the banner + KEX handshake after connect.
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
    #[error("identity too large: {0}")]
    IdentityTooLarge(String),
    #[error("malformed assignment: {0}")]
    MalformedIdentity(String),
}

impl ProbeFailure {
    /// The wire failure category this failure maps to.
    fn category(&self) -> ProbeFailureCategory {
        match self {
            ProbeFailure::DnsResolutionFailed(_) => ProbeFailureCategory::DnsResolutionFailed,
            ProbeFailure::ConnectionRefused(_) => ProbeFailureCategory::ConnectionRefused,
            ProbeFailure::ConnectionTimeout(_) => ProbeFailureCategory::ConnectionTimeout,
            ProbeFailure::ProtocolMismatch(_) => ProbeFailureCategory::ProtocolMismatch,
            ProbeFailure::IdentityTooLarge(_) => ProbeFailureCategory::IdentityTooLarge,
            ProbeFailure::MalformedIdentity(_) => ProbeFailureCategory::MalformedIdentity,
        }
    }
}

/// Run the probe described by `assignment` and map the outcome to a single
/// terminal [`ProbeResult`], honoring the assignment's total deadline. This is
/// the control-loop entry point: it always returns exactly one result (a
/// Succeeded result with evidence, or a Failed result with a category + detail).
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

    let (host, port) = match &assignment.endpoint {
        Some(probe_assignment::Endpoint::Ssh(e)) => (e.host.as_str(), e.port),
        _ => ("", 0),
    };
    match outcome {
        Ok(obs) => {
            tracing::info!(
                host,
                port,
                algorithm = %obs.algorithm,
                fingerprint = %obs.sha256_fingerprint,
                connect_ms = obs.connect_ms,
                handshake_ms = obs.handshake_ms,
                resolved = obs.resolved_addresses.len(),
                "ssh host identity probe succeeded",
            );
            success_result(&assignment, &obs)
        }
        Err(f) => {
            tracing::warn!(
                host,
                port,
                category = ?f.category(),
                detail = %f,
                "ssh host identity probe failed",
            );
            failure_result(&assignment, f.category(), f.to_string())
        }
    }
}

/// Probe the SSH endpoint in `assignment` and return its observed host identity.
/// Enforces the per-phase deadlines (DNS / connect / handshake) and the banner
/// bound from the assignment's [`ProbeLimits`]. The total deadline is applied by
/// [`run_to_result`].
pub async fn run(assignment: &ProbeAssignment) -> Result<ProbeObservation, ProbeFailure> {
    let endpoint = match &assignment.endpoint {
        Some(probe_assignment::Endpoint::Ssh(e)) => e,
        _ => {
            return Err(ProbeFailure::MalformedIdentity(
                "assignment is not an SSH endpoint".into(),
            ))
        }
    };
    let limits = assignment.limits.as_ref().ok_or_else(|| {
        ProbeFailure::MalformedIdentity("assignment carries no probe limits".into())
    })?;
    probe_ssh(&endpoint.host, endpoint.port as u16, limits).await
}

async fn probe_ssh(
    host: &str,
    port: u16,
    limits: &ProbeLimits,
) -> Result<ProbeObservation, ProbeFailure> {
    // Resolve (records the addresses observed) under the DNS deadline.
    let dns_timeout = ms(limits.dns_timeout_ms);
    let addrs: Vec<SocketAddr> =
        match timeout(dns_timeout, tokio::net::lookup_host((host, port))).await {
            Ok(Ok(iter)) => iter.collect(),
            Ok(Err(e)) => return Err(ProbeFailure::DnsResolutionFailed(e.to_string())),
            Err(_) => {
                return Err(ProbeFailure::DnsResolutionFailed(
                    "DNS lookup timed out".into(),
                ))
            }
        };
    if addrs.is_empty() {
        return Err(ProbeFailure::DnsResolutionFailed(format!(
            "{host}:{port} resolved to no addresses"
        )));
    }
    let resolved_addresses: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();

    // Connect (first address that answers) under the connect deadline.
    let connect_timeout = ms(limits.connect_timeout_ms);
    let connect_start = Instant::now();
    let stream = connect_any(&addrs, connect_timeout).await?;
    let _ = stream.set_nodelay(true);
    let connect_ms = connect_start.elapsed().as_millis() as i64;

    // Banner read + KEX under the handshake deadline. A stalled peer trips this.
    let handshake_timeout = ms(limits.handshake_timeout_ms);
    let max_banner = limits.max_banner_bytes.max(1) as usize;
    let handshake_start = Instant::now();
    let (banner, host_key) = match timeout(handshake_timeout, handshake(stream, max_banner)).await {
        Ok(r) => r?,
        Err(_) => {
            return Err(ProbeFailure::ConnectionTimeout(
                "SSH handshake did not complete before the deadline".into(),
            ))
        }
    };
    let handshake_ms = handshake_start.elapsed().as_millis() as i64;

    let openssh_public_line = host_key
        .to_openssh()
        .map_err(|e| ProbeFailure::ProtocolMismatch(format!("host key not serializable: {e}")))?;

    Ok(ProbeObservation {
        algorithm: host_key.algorithm().to_string(),
        sha256_fingerprint: host_key.fingerprint(Default::default()).to_string(),
        openssh_public_line,
        banner,
        resolved_addresses,
        connect_ms,
        handshake_ms,
    })
}

/// Try each resolved address in turn, returning the first TCP connection that
/// succeeds within `per_addr_timeout`. Maps the last error to a category.
async fn connect_any(
    addrs: &[SocketAddr],
    per_addr_timeout: Duration,
) -> Result<TcpStream, ProbeFailure> {
    let mut last: Option<ProbeFailure> = None;
    for addr in addrs {
        match timeout(per_addr_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
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

/// Read the server identification banner (enforcing `max_banner`) then run the
/// russh transport handshake, returning the banner and the captured host key.
///
/// russh owns the SSH identification exchange, but does not surface the server's
/// banner to the returned handle. We peel the identification line off the socket
/// ourselves — which is also where `max_banner_bytes` is enforced — then replay
/// the consumed bytes to russh via [`RejoinedStream`] so its own handshake sees a
/// pristine stream.
async fn handshake(
    stream: TcpStream,
    max_banner: usize,
) -> Result<(String, PublicKey), ProbeFailure> {
    let (mut read, write) = stream.into_split();
    let (consumed, banner) = read_banner(&mut read, max_banner).await?;
    let rejoined = RejoinedStream {
        read: std::io::Cursor::new(consumed).chain(read),
        write,
    };

    let captured: Arc<Mutex<Option<PublicKey>>> = Arc::new(Mutex::new(None));
    let handler = ProbeHandler {
        captured: captured.clone(),
    };
    let config = Arc::new(probe_client_config());

    // connect_stream returns AFTER KEX + check_server_key but BEFORE any
    // user-auth. We drop the handle without authenticating: no USERAUTH is sent.
    let handle = russh::client::connect_stream(config, rejoined, handler)
        .await
        .map_err(map_russh_error)?;
    drop(handle);

    let host_key = captured.lock().unwrap().take().ok_or_else(|| {
        ProbeFailure::ProtocolMismatch("no host key was presented during key exchange".into())
    })?;
    Ok((banner, host_key))
}

/// Read from `read` until the server's `SSH-...` identification line, enforcing
/// `max_banner`. Returns (all bytes consumed, the ident line without its CR/LF).
/// RFC 4253 §4.2 permits the server to send preliminary lines before the `SSH-`
/// line; we skip those so the reported banner is the actual ident string. All
/// consumed bytes (pre-banner lines included) are replayed to russh, which runs
/// its own identification exchange over them.
async fn read_banner(
    read: &mut OwnedReadHalf,
    max_banner: usize,
) -> Result<(Vec<u8>, String), ProbeFailure> {
    let mut consumed = Vec::with_capacity(64);
    let mut chunk = [0u8; 256];
    let mut scanned = 0usize; // index past the last line terminator already inspected
    loop {
        let n = read
            .read(&mut chunk)
            .await
            .map_err(|e| ProbeFailure::ProtocolMismatch(format!("reading SSH banner: {e}")))?;
        if n == 0 {
            return Err(ProbeFailure::ProtocolMismatch(
                "connection closed before SSH identification string".into(),
            ));
        }
        consumed.extend_from_slice(&chunk[..n]);
        // Inspect each newly-completed line; return the first `SSH-` one, skip
        // any preliminary lines before it.
        while let Some(rel) = consumed[scanned..].iter().position(|&b| b == b'\n') {
            let end = scanned + rel;
            let line = String::from_utf8_lossy(&consumed[scanned..end])
                .trim_end_matches('\r')
                .to_string();
            scanned = end + 1;
            if line.starts_with("SSH-") {
                return Ok((consumed, line));
            }
        }
        if consumed.len() > max_banner {
            return Err(ProbeFailure::IdentityTooLarge(format!(
                "SSH identification exceeded {max_banner} bytes before an SSH- line"
            )));
        }
    }
}

/// russh client Config for probing. Narrows the default host-key algorithm set to
/// drop SHA-1 RSA (`rsa` with no hash) so we never negotiate a SHA-1 signature
/// merely to enumerate a host key (Step 3 policy). DSA is already absent from the
/// default. The remaining set is Ed25519, ECDSA P-256/384/521, RSA-SHA-512/256.
fn probe_client_config() -> russh::client::Config {
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
    let key = vec![
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    ];
    russh::client::Config {
        preferred: russh::Preferred {
            key: Cow::Owned(key),
            ..russh::Preferred::DEFAULT
        },
        ..Default::default()
    }
}

/// Map a russh handshake error to a probe failure. russh does not expose a
/// structured reason for most transport failures, so anything that isn't clearly
/// a connection loss is reported as a protocol mismatch (the peer did not speak
/// SSH the way we expect).
fn map_russh_error(e: russh::Error) -> ProbeFailure {
    match e {
        russh::Error::IO(io) => match io.kind() {
            std::io::ErrorKind::TimedOut => {
                ProbeFailure::ConnectionTimeout(format!("SSH handshake I/O timed out: {io}"))
            }
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => ProbeFailure::ProtocolMismatch(format!(
                "SSH connection lost during handshake: {io}"
            )),
            _ => ProbeFailure::ProtocolMismatch(format!("SSH handshake I/O error: {io}")),
        },
        other => ProbeFailure::ProtocolMismatch(format!("SSH handshake failed: {other}")),
    }
}

/// A split TCP stream whose already-consumed identification-banner bytes are
/// replayed to the reader ahead of the live socket, so russh performs its own
/// identification exchange on a stream that looks untouched. Reads flow through
/// the replay-then-socket chain; writes go straight to the socket.
struct RejoinedStream {
    read: tokio::io::Chain<std::io::Cursor<Vec<u8>>, OwnedReadHalf>,
    write: OwnedWriteHalf,
}

impl AsyncRead for RejoinedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for RejoinedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

/// russh client handler for a probe: snapshot the presented host key and accept
/// it (the probe observes identity; it never authenticates or enforces a pin).
struct ProbeHandler {
    captured: Arc<Mutex<Option<PublicKey>>>,
}

impl russh::client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        *self.captured.lock().unwrap() = Some(server_public_key.clone());
        Ok(true)
    }
}

/// Clamp a non-positive millisecond bound to 1ms so a misconfigured limit never
/// yields a zero (== immediate) or negative timeout.
fn ms(millis: i64) -> Duration {
    Duration::from_millis(millis.max(1) as u64)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Build a Succeeded [`ProbeResult`] carrying the observed host-key evidence and
/// SSH metadata. Only public identifiers from the assignment are echoed back.
fn success_result(pa: &ProbeAssignment, obs: &ProbeObservation) -> ProbeResult {
    let evidence = ProbeEvidence {
        kind: ProbeEvidenceKind::SshHostKey as i32,
        algorithm: obs.algorithm.clone(),
        sha256_fingerprint: obs.sha256_fingerprint.clone(),
        public_material: obs.openssh_public_line.clone(),
        ..Default::default()
    };
    ProbeResult {
        job_id: pa.job_id.clone(),
        asset_id: pa.asset_id.clone(),
        endpoint_revision: pa.endpoint_revision,
        lease_token: pa.lease_token.clone(),
        protocol: pa.protocol,
        outcome: ProbeOutcome::Succeeded as i32,
        observed_at_unix_ms: now_unix_ms(),
        resolved_addresses: obs.resolved_addresses.clone(),
        evidence: vec![evidence],
        failure_category: ProbeFailureCategory::Unspecified as i32,
        failure_detail: String::new(),
        protocol_metadata: Some(probe_result::ProtocolMetadata::Ssh(ProbeSshMetadata {
            banner: obs.banner.clone(),
            // russh does not surface the server's offered host-key algorithm list
            // (only the single negotiated key, already in the evidence above), so
            // we leave this empty rather than fabricate a misleading one-element list.
            host_key_algorithms: Vec::new(),
        })),
    }
}

/// Build a Failed [`ProbeResult`] with a category and detail.
///
/// ponytail: resolved_addresses are dropped on failure — threading them out of
/// `run` would mean carrying a Vec on every `ProbeFailure` variant for a
/// diagnostics-only field. Add if failure diagnostics need the resolved IPs.
fn failure_result(
    pa: &ProbeAssignment,
    category: ProbeFailureCategory,
    detail: String,
) -> ProbeResult {
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
