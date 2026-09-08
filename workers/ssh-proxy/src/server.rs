//! ssh-proxy data-plane front door + SSH auth gate.
//!
//! Accepts the gateway's mesh mTLS connection (client cert pinned to the
//! gateway's SPIFFE id), reads the HTTP/1.1 CONNECT preamble to obtain the
//! session `token`, then runs a russh SSH server over the already-authenticated
//! tunnel. The client authenticates with **publickey** using its ephemeral key
//! `Kc` (whose fingerprint is the token's `cnf`).
//!
//! On the offered key + requested login the worker:
//! 1. generates a fresh per-session key `Kw` (ed25519),
//! 2. calls `SetupSession(token, worker_id, Kc.pub, Kw.pub)` on warden,
//! 3. warden verifies `cnf == fp(Kc)`, re-checks the entitlement, and returns
//!    `{session_id, target_address, cert-over-Kw}`,
//! 4. the worker requires every cert principal to be `<login>@<scope>`
//!    (host-scoped), that the cert is over `Kw`, caches the session, and
//!    **Accepts** (russh then verifies the client's signature over `Kc` —
//!    proof-of-possession). The host binding is enforced by the target's
//!    `AuthorizedPrincipalsFile`.
//!
//! Any failure — SetupSession error, cert parse failure, cert not over `Kw`,
//! principals not scoped to the requested login — is a hard **Reject**. We NEVER
//! accept on error.
//!
//! The security decision is isolated in [`authorize`] (a pure async fn over an
//! injected [`SetupFn`]) so it is unit-testable without a real warden or a live
//! russh handshake. The russh [`Handler::auth_publickey`] is a thin wrapper that
//! calls it. Once auth succeeds, the client's session/pty/shell (or exec)
//! requests drive the second hop: the worker dials the target with `Kw` + the
//! certificate, opens a matching channel, and bridges the two.

use std::fs;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use russh::keys::ssh_key::{Certificate, PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::control::SessionRegistry;

/// Current wall-clock time as unix milliseconds (saturating at 0 before the
/// epoch). Used to stamp recording start/end timestamps.
pub(crate) fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
use crate::setup::{
    issue_session_credential, prepare_session, IssueOutcome, PrepareOutcome, TargetCredential,
    TrustAnchor,
};
use crate::{proxy, target};
use jumpgate_mesh::tls::MeshClientCerts;
use subtle::ConstantTimeEq;

/// The enforced verify-before-issue target hop, shared by the SSH and
/// browser-terminal ingresses so both observe the STRICT order and neither can
/// release a credential to an unverified target.
///
/// Order:
/// 1. connect + KEX to the target, observing its host key WITHOUT authenticating;
/// 2. constant-time match the observed SHA-256 fingerprint against an approved
///    `ssh_host_key` anchor (fail closed on mismatch / no anchor / host-CA anchor —
///    `IssueSessionCredential` is NEVER called on a failure here);
/// 3. `IssueSessionCredential` over `Kw` (the credential first exists HERE);
/// 4. authenticate the (already-connected) target with the released credential.
///
/// Returns the connected+authenticated handle. On failure the caller aborts the
/// hop (never bridges) and reports the session ended.
pub(crate) async fn verify_and_dial_target(
    prepared: &PreparedSession,
    login: &str,
    issue: &IssueFn,
) -> Result<russh::client::Handle<target::TargetHandler>, HopError> {
    // 1. Connect + KEX. The handle is connected-but-unauthenticated; we observe
    //    the host key but present NO credential until it is verified.
    let (mut handle, observed) = target::connect_observe(&prepared.target_address)
        .await
        .map_err(HopError::Connect)?;

    // 2. Match the observed identity against an approved anchor. A failure here is
    //    terminal and MUST NOT reach IssueSessionCredential — we drop the
    //    unauthenticated connection with no credential ever requested.
    let matched = match_anchor(&observed, &prepared.anchors).map_err(|why| {
        // The mismatch observation: the public identity the target actually
        // presented, recorded for operators. No secret is involved.
        tracing::warn!(
            session_id = %prepared.session_id,
            target = %prepared.target_address,
            observed_algorithm = %observed.algorithm(),
            observed_fingerprint = %observed.fingerprint(Default::default()),
            reason = why.log_detail(),
            "target host identity did NOT match an approved anchor; refusing session before credential issuance",
        );
        HopError::Identity(why)
    })?;

    // 3. Only now — after a successful match — request the credential over Kw.
    let kw_pub = public_key_line(prepared.kw.public_key())
        .map_err(|e| HopError::Credential(e.to_string()))?;
    let outcome: IssueOutcome = issue(
        prepared.session_id.clone(),
        prepared.endpoint_revision,
        matched.anchor_id,
        matched.observed_fingerprint,
        kw_pub,
    )
    .await
    .map_err(|e| HopError::Credential(e.to_string()))?;

    // 4. Validate the released credential and authenticate the verified target.
    let target_auth =
        build_target_auth(outcome.credential, &prepared.kw, login).map_err(HopError::Credential)?;
    match &target_auth {
        TargetAuth::Cert { certificate, kw } => {
            target::authenticate_cert_on(&mut handle, login, kw, certificate).await
        }
        TargetAuth::Password(password) => {
            target::authenticate_password_on(&mut handle, login, password).await
        }
        TargetAuth::Key(pem) => target::authenticate_publickey_on(&mut handle, login, pem).await,
    }
    .map_err(|e| HopError::Credential(e.to_string()))?;

    Ok(handle)
}

/// The anchor the worker matched, threaded into `IssueSessionCredential`.
#[derive(Debug)]
struct AnchorMatch {
    anchor_id: String,
    observed_fingerprint: String,
}

/// Why the observed target identity did not resolve to an approved anchor. Both
/// variants fail closed and map to the SAME client-safe reason; the distinction is
/// for the server-side observation log only.
#[derive(Debug, Clone, Copy)]
pub enum IdentityError {
    /// No approved `ssh_host_key` anchor matched the observed host key — a changed
    /// key, an unknown target, or no anchors at all. The MITM / unverified signal.
    Unmatched,
    /// The applicable anchor is a host-CA anchor. russh 0.62 never surfaces the
    /// target's host CERTIFICATE (only its plain host KEY — see `probe.rs` and the
    /// Task 6 finding), so a CA anchor cannot be verified at session time. Fail
    /// closed rather than accept-any or fake a CA match.
    CaUnsupported,
}

impl IdentityError {
    fn log_detail(self) -> &'static str {
        match self {
            IdentityError::Unmatched => "no approved ssh_host_key anchor matched the observed key",
            IdentityError::CaUnsupported => {
                "only a host-CA anchor applies; unverifiable at session time with russh 0.62"
            }
        }
    }
}

/// Match the observed target host key against the prepared trust anchors.
///
/// Only exact-key (`ssh_host_key`) anchors are verifiable at SSH session time: the
/// observed host key's SHA-256 fingerprint is compared with each anchor's stored
/// fingerprint using CONSTANT-TIME byte equality. On the first match the anchor's
/// id is selected. Host-CA anchors fail closed (russh 0.62 cannot obtain the host
/// certificate; see [`IdentityError::CaUnsupported`]). No match → fail closed.
fn match_anchor(
    observed: &PublicKey,
    anchors: &[TrustAnchor],
) -> Result<AnchorMatch, IdentityError> {
    let observed_fp = observed.fingerprint(Default::default()).to_string();
    let observed_bytes = observed_fp.as_bytes();

    let mut saw_ca_anchor = false;
    for anchor in anchors {
        match anchor.kind.as_str() {
            "ssh_host_key" => {
                let anchor_bytes = anchor.sha256_fingerprint.as_bytes();
                // Constant-time equality is only meaningful over equal-length
                // slices; the length of a public fingerprint is not a secret, so
                // gating on it first is safe.
                if anchor_bytes.len() == observed_bytes.len()
                    && bool::from(anchor_bytes.ct_eq(observed_bytes))
                {
                    return Ok(AnchorMatch {
                        anchor_id: anchor.id.clone(),
                        observed_fingerprint: observed_fp,
                    });
                }
            }
            "ssh_host_ca" => saw_ca_anchor = true,
            // tls_leaf / tls_ca are not SSH identities; ignore them here.
            _ => {}
        }
    }

    if saw_ca_anchor {
        Err(IdentityError::CaUnsupported)
    } else {
        Err(IdentityError::Unmatched)
    }
}

/// Validate a released credential and build the [`TargetAuth`] the target hop
/// authenticates with. For the `Cert` (ca) kind the certificate MUST parse, be
/// over `Kw` (the only key the worker presents), and carry only `<login>@<scope>`
/// principals. `Password`/`Key` are cached as-is (warden already enforced the
/// entitlement). Any failure is a hard error (the caller aborts the hop).
fn build_target_auth(
    credential: TargetCredential,
    kw: &PrivateKey,
    login: &str,
) -> Result<TargetAuth, String> {
    match credential {
        TargetCredential::Cert(cert_bytes) => {
            let cert_str = String::from_utf8(cert_bytes)
                .map_err(|e| format!("released certificate is not utf-8: {e}"))?;
            let certificate = Certificate::from_openssh(cert_str.trim())
                .map_err(|e| format!("released certificate failed to parse: {e}"))?;

            // The cert MUST certify Kw — the only key we present on the target hop.
            if certificate.public_key() != kw.public_key().key_data() {
                return Err("released certificate is not over the worker's session key Kw".into());
            }

            // Every principal MUST be host-scoped to the requested login
            // (`<login>@<scope>`). The host binding is enforced target-side by its
            // AuthorizedPrincipalsFile.
            let principals = certificate.valid_principals();
            let login_prefix = format!("{login}@");
            if principals.is_empty() || !principals.iter().all(|p| p.starts_with(&login_prefix)) {
                return Err(format!(
                    "released certificate principals {principals:?} are not all scoped to login {login:?}"
                ));
            }

            Ok(TargetAuth::Cert {
                certificate: Box::new(certificate),
                kw: Box::new(kw.clone()),
            })
        }
        TargetCredential::Password(password) => Ok(TargetAuth::Password(password)),
        TargetCredential::Key(pem) => Ok(TargetAuth::Key(pem)),
    }
}

/// How the verify-before-issue target hop ([`verify_and_dial_target`]) failed,
/// mapped by the caller to a client-safe message + a live-session end reason. The
/// three variants exist so an identity refusal (no credential ever issued) is
/// never conflated with a plain connectivity failure.
#[derive(Debug)]
pub enum HopError {
    /// The target's identity did not match an approved anchor. IssueSessionCredential
    /// was NOT called. Client-safe: "target identity could not be verified".
    Identity(IdentityError),
    /// Connect/KEX to the target failed (unreachable, protocol error).
    Connect(anyhow::Error),
    /// IssueSessionCredential failed, the released credential was invalid, or the
    /// target rejected the credential.
    Credential(String),
}

impl HopError {
    /// The stable live-session end reason reported to warden.
    pub fn reason(&self) -> &'static str {
        match self {
            // Stable machine-readable token for CLI/UI rendering (covers both
            // Unmatched and CaUnsupported — one token by design). The human-readable
            // client message stays generic (see `client_message`).
            HopError::Identity(_) => "target_identity_mismatch",
            HopError::Connect(_) => "target_unavailable",
            HopError::Credential(_) => "credential_rejected",
        }
    }

    /// The stable, generic client-facing message (never leaks which check failed).
    pub fn client_message(&self) -> &'static str {
        match self {
            HopError::Identity(_) => "target identity could not be verified",
            HopError::Connect(_) => "target unavailable",
            HopError::Credential(_) => "session credential rejected",
        }
    }
}

/// Build a streaming recorder: a multipart upload to the recording bucket under
/// `object_key`, fed by [`crate::record::spawn_recorder`], with the asciicast
/// header sized to `width`x`height`.
///
/// Returns the tap handle, the recorder task's join handle, and the recording's
/// start timestamp (unix ms). Fails when recording is not configured (no bucket)
/// or the object store rejects the multipart-upload create — either is a
/// fail-closed trigger for a `recording_required` session. Shared by the SSH and
/// browser-terminal ingresses so recordings are byte-identical across both.
pub(crate) async fn build_recorder(
    recording: &RecordingSettings,
    object_key: &str,
    width: u16,
    height: u16,
) -> anyhow::Result<(
    crate::record::RecorderHandle,
    tokio::task::JoinHandle<crate::record::RecordingReport>,
    i64,
)> {
    if recording.bucket.is_empty() {
        anyhow::bail!("recording bucket not configured");
    }
    let uploader = crate::record::S3Uploader::create(
        &recording.endpoint,
        &recording.region,
        &recording.bucket,
        object_key.to_string(),
    )
    .await?;

    let (width, height) = if width != 0 && height != 0 {
        (width, height)
    } else {
        (80, 24)
    };
    let started_ms = unix_millis_now();
    let header = crate::asciicast::Header::new(width, height, started_ms / 1000);

    let (handle, join) = crate::record::spawn_recorder(
        uploader,
        header,
        crate::record::RecorderConfig {
            part_size: recording.part_size,
            channel_bound: 1024,
        },
    );
    Ok((handle, join, started_ms))
}

/// How the worker authenticates the second hop to the target, discriminated by
/// the asset login's configured kind:
/// - `Cert`: OpenSSH certificate-with-key auth. `kw` is the per-session private
///   key the target hop presents together with `certificate`, the OpenSSH cert
///   warden minted over `kw.public_key()`.
/// - `Password`: a plain stored password injected as the target's password auth.
/// - `Key`: a plain stored OpenSSH private-key PEM injected as publickey auth.
///
/// `Password`/`Key` carry warden-injected secrets that never touch the client;
/// they are held in [`Zeroizing`] (scrubbed on drop) and [`Debug`] is
/// hand-written to redact every secret (the `Cert` arm's `kw` private key
/// included) so a stray `?target_auth` in a log can never print one.
pub enum TargetAuth {
    // Boxed: the cert + key make this variant far larger than the secret ones.
    Cert {
        certificate: Box<Certificate>,
        kw: Box<PrivateKey>,
    },
    Password(Zeroizing<String>),
    Key(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for TargetAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cert { .. } => write!(f, "Cert {{ certificate: <cert>, kw: <redacted> }}"),
            Self::Password(_) => write!(f, "Password(<redacted>)"),
            Self::Key(_) => write!(f, "Key(<redacted>)"),
        }
    }
}

/// A prepared session: the credential-free outcome of a successful `PrepareSession`
/// (accepted at publickey-auth time). It carries the endpoint, the trust anchors
/// the observed target must match, and the per-session key `Kw` — but NO credential.
/// The credential is released only at target-hop time, after the identity match
/// (see [`verify_and_dial_target`]).
pub struct PreparedSession {
    pub session_id: String,
    /// The asset's endpoint revision at prepare time, echoed to IssueSessionCredential
    /// so warden rejects a match against an endpoint that moved under the session.
    pub endpoint_revision: i64,
    pub target_address: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Echoed back in the recording report for session attribution.
    pub grant_id: String,
    /// The asset's current active trust anchors; the observed target host key must
    /// match one (constant-time) before a credential is released.
    pub anchors: Vec<TrustAnchor>,
    /// The fresh per-session key. Certified over at issue time (ca) or unused
    /// (password/key). Kept so the credential is minted over exactly this key.
    pub kw: PrivateKey,
    /// warden requires this session to be recorded; if a recording cannot be
    /// established (or a write fails mid-session) the session is refused/torn down.
    pub recording_required: bool,
    /// The object key warden assigned for this session's recording.
    pub recording_object_key: String,
}

/// Recording store settings the target hop needs to build an uploader. An empty
/// `bucket` disables recording (used by tests and unconfigured deployments).
#[derive(Clone)]
pub struct RecordingSettings {
    pub bucket: String,
    pub endpoint: String,
    pub region: String,
    pub part_size: usize,
}

impl RecordingSettings {
    /// Recording disabled: no bucket configured. `build_recorder` fails closed on
    /// this when a session is marked `recording_required`.
    pub fn disabled() -> Self {
        Self {
            bucket: String::new(),
            endpoint: String::new(),
            region: String::new(),
            part_size: crate::record::MIN_PART_SIZE,
        }
    }
}

/// What the data plane reports to the control stream when a session ends.
pub struct SessionEndReport {
    pub session_id: String,
    pub reason: String,
    pub recording: Option<RecordingOutcome>,
}

/// The recorded-session disposition carried to warden.
pub struct RecordingOutcome {
    pub object_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub started_at_unix_ms: i64,
    pub ended_at_unix_ms: i64,
    pub status: String, // "completed" | "failed"
    /// The access grant that authorized the session (empty for standing-only
    /// access), for warden to attribute the recording.
    pub grant_id: String,
}

/// A built recorder: the tap handle fed into the bridge/pump, the recorder task's
/// join handle, and the recording start timestamp (unix ms). Returned by
/// [`build_recorder`] and finalized by [`finalize_recording`].
pub(crate) type Recorder = (
    crate::record::RecorderHandle,
    tokio::task::JoinHandle<crate::record::RecordingReport>,
    i64,
);

/// Finalize a session's recorder into the [`RecordingOutcome`] reported to warden,
/// shared by the SSH and browser-terminal ingresses so the fail-closed finalize
/// path exists in ONE place (drift here silently weakens the recording guarantee).
///
/// `success` is `true` for a clean session end (complete the upload) and `false`
/// for a recording failure or a target-hop failure (abort the upload). The
/// recorder task is awaited for the authoritative report; a join failure maps to a
/// `failed` outcome. A `None` recorder (unrecorded session) yields `None`.
pub(crate) async fn finalize_recording(
    recorder: Option<Recorder>,
    success: bool,
    session_id: &str,
    object_key: &str,
    grant_id: &str,
) -> Option<RecordingOutcome> {
    let (handle, join, started_ms) = recorder?;
    if success {
        handle.finish().await;
    } else {
        handle.fail().await;
    }
    let report = join.await.unwrap_or_else(|e| {
        tracing::warn!(%session_id, error = %e, "recorder task join failed");
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
        object_key: object_key.to_string(),
        size_bytes: report.size_bytes,
        sha256: report.sha256_hex,
        started_at_unix_ms: started_ms,
        ended_at_unix_ms: unix_millis_now(),
        status: status.into(),
        grant_id: grant_id.to_string(),
    })
}

/// A synthetic `failed` recording outcome for a `recording_required` session whose
/// recorder could never be built (nothing was ever uploaded). Reported when the
/// session is refused up front.
pub(crate) fn failed_recording_outcome(object_key: &str, grant_id: &str) -> RecordingOutcome {
    RecordingOutcome {
        object_key: object_key.to_string(),
        size_bytes: 0,
        sha256: String::new(),
        started_at_unix_ms: 0,
        ended_at_unix_ms: 0,
        status: "failed".into(),
        grant_id: grant_id.to_string(),
    }
}

/// Pseudo-terminal parameters remembered from the client's `pty_request`, so the
/// worker requests a matching pty on the target before starting the shell/exec.
#[derive(Clone)]
struct PtyParams {
    term: String,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    modes: Vec<(Pty, u32)>,
}

/// Why publickey auth (the [`prepare`] phase) was rejected. Both variants map to
/// `Auth::Reject` — the distinction exists for logging/tests only, never to leak
/// to the client. The credential checks (cert-over-`Kw`, host-scoped principals)
/// now live in [`build_target_auth`] at issue time, not here.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("PrepareSession failed: {0}")]
    Setup(String),
    #[error("failed to serialize public key: {0}")]
    KeySerialize(String),
}

/// The `PrepareSession` call, injected so [`prepare`] can be tested without a real
/// warden. Takes the requested `login` plus the OpenSSH public-key bytes for `Kc`;
/// returns warden's credential-free outcome or an error (a hard reject).
pub type PrepareFn = Arc<
    dyn Fn(
            String,  // login (the client's requested SSH username)
            Vec<u8>, // kc_pub (authorized_keys line; empty for web mode)
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<PrepareOutcome>> + Send>>
        + Send
        + Sync,
>;

/// The `IssueSessionCredential` call, injected so the target-hop verify path can be
/// tested without a real warden. Called ONLY after the observed target identity
/// matched an anchor; takes the session id, the prepared endpoint revision, the
/// matched anchor id, the observed fingerprint, and `Kw`'s public-key bytes;
/// returns the released credential or an error (a hard reject).
pub type IssueFn = Arc<
    dyn Fn(
            String,  // session_id
            i64,     // endpoint_revision (prepared against)
            String,  // matched_anchor_id
            String,  // observed_fingerprint
            Vec<u8>, // kw_pub (authorized_keys line)
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<IssueOutcome>> + Send>>
        + Send
        + Sync,
>;

/// Serialize an `ssh_key::PublicKey` to its OpenSSH authorized_keys line bytes —
/// the form warden's `parseSSHPublicKey` accepts first.
fn public_key_line(pk: &PublicKey) -> Result<Vec<u8>, AuthError> {
    pk.to_openssh()
        .map(String::into_bytes)
        .map_err(|e| AuthError::KeySerialize(e.to_string()))
}

/// The publickey-auth decision (phase 1 of the two-phase flow), isolated from russh.
///
/// Generates a fresh `Kw` and calls `PrepareSession` (via the injected `prepare`)
/// with the requested `login` + the offered `Kc`. warden verifies `cnf == fp(Kc)`,
/// re-checks the login entitlement, records the live session, and returns the
/// endpoint + the asset's trust anchors — but NO credential. Accepting the SSH auth
/// on a successful `PrepareSession` therefore carries no secret: the credential is
/// released later, only after the worker matches the target's observed identity
/// (see [`verify_and_dial_target`]).
///
/// `kc` is the client's ephemeral key for the SSH ingress (proof-of-possession
/// binds it via the token's `cnf`). The browser-terminal ingress has no client
/// key: it passes `None`, which sends an EMPTY client key — warden's `mode=web`
/// tokens skip the `cnf` proof and take the login from the ticket.
///
/// Returns the cached [`PreparedSession`] on success; ANY failure is an
/// [`AuthError`] and the caller MUST reject. It never returns `Ok` on error.
pub async fn prepare(
    login: &str,
    kc: Option<&PublicKey>,
    prepare_fn: &PrepareFn,
) -> Result<PreparedSession, AuthError> {
    // Fresh per-session Kw (ed25519), generated now and held until issue time so
    // the credential is minted over exactly this key. Infallible in practice;
    // treat a keygen failure as a setup-class error rather than ever accepting.
    let kw = PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
        .map_err(|e| AuthError::Setup(format!("generate Kw: {e}")))?;

    // An SSH-ingress client offers its Kc; the browser terminal has none, so we
    // send an empty client key (warden's web tokens carry no `cnf` to prove).
    let kc_pub = match kc {
        Some(kc) => public_key_line(kc)?,
        None => Vec::new(),
    };

    // Redeem the token (credential-free). A transport/authorization error is a
    // hard reject.
    let outcome = prepare_fn(login.to_string(), kc_pub)
        .await
        .map_err(|e| AuthError::Setup(e.to_string()))?;

    Ok(PreparedSession {
        session_id: outcome.session_id,
        endpoint_revision: outcome.endpoint_revision,
        target_address: outcome.target_address,
        grant_id: outcome.grant_id,
        anchors: outcome.anchors,
        kw,
        recording_required: outcome.recording_required,
        recording_object_key: outcome.recording_object_key,
    })
}

/// Build the injected warden fns for a connection: a [`PrepareFn`] and an
/// [`IssueFn`] closing over the worker's mesh identity + warden coordinates.
/// Shared by the SSH ingress ([`SshHandler::new`]) and the browser-terminal
/// ingress so both drive the identical two-phase flow against a real warden.
pub(crate) fn warden_fns(
    token: String,
    worker_id: String,
    warden_addr: String,
    warden_spiffe: String,
    certs: Arc<MeshClientCerts>,
) -> (PrepareFn, IssueFn) {
    let prepare_fn: PrepareFn = {
        let token = token.clone();
        let worker_id = worker_id.clone();
        let warden_addr = warden_addr.clone();
        let warden_spiffe = warden_spiffe.clone();
        let certs = certs.clone();
        Arc::new(move |login, kc_pub| {
            let token = token.clone();
            let worker_id = worker_id.clone();
            let warden_addr = warden_addr.clone();
            let warden_spiffe = warden_spiffe.clone();
            let certs = certs.clone();
            Box::pin(async move {
                prepare_session(
                    &warden_addr,
                    &warden_spiffe,
                    &certs,
                    &token,
                    &worker_id,
                    &login,
                    kc_pub,
                )
                .await
            })
        })
    };

    let issue_fn: IssueFn = Arc::new(
        move |session_id, endpoint_revision, matched_anchor_id, observed_fingerprint, kw_pub| {
            let worker_id = worker_id.clone();
            let warden_addr = warden_addr.clone();
            let warden_spiffe = warden_spiffe.clone();
            let certs = certs.clone();
            Box::pin(async move {
                issue_session_credential(
                    &warden_addr,
                    &warden_spiffe,
                    &certs,
                    &session_id,
                    &worker_id,
                    endpoint_revision,
                    &matched_anchor_id,
                    &observed_fingerprint,
                    kw_pub,
                )
                .await
            })
        },
    );

    (prepare_fn, issue_fn)
}

/// Per-connection SSH server handler. Holds the CONNECT token + shared deps, and
/// (after a successful auth) the cached [`PreparedSession`], the requested login,
/// the accepted client channel, and any pty parameters — everything the
/// shell/exec trigger needs to verify the target, obtain the credential, and start
/// the bridge.
pub struct SshHandler {
    /// PrepareSession (phase 1, at auth time) + IssueSessionCredential (phase 2, at
    /// target-hop time, after the identity match). Injected so tests stub warden.
    prepare_fn: PrepareFn,
    issue_fn: IssueFn,
    /// Force-close registry + finished-session reporter, shared with the control
    /// plane so warden can tear a live session down and learn when it ends.
    registry: SessionRegistry,
    session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
    /// Recording store settings, used to build the per-session uploader.
    recording: RecordingSettings,
    /// Cached after a successful publickey auth (credential-free); consumed by the
    /// target hop, which verifies the target then issues the credential.
    state: Option<PreparedSession>,
    /// The login the client authenticated as (a cert principal).
    login: Option<String>,
    /// The client's session channel, accepted in `channel_open_session`.
    client_channel: Option<Channel<Msg>>,
    /// Remembered pty request, replayed on the target before shell/exec.
    pty: Option<PtyParams>,
}

impl SshHandler {
    /// Build a handler that redeems `token` via real PrepareSession /
    /// IssueSessionCredential calls to `warden_addr` (pinned to `warden_spiffe`) as
    /// `worker_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: String,
        worker_id: String,
        warden_addr: String,
        warden_spiffe: String,
        certs: Arc<MeshClientCerts>,
        registry: SessionRegistry,
        session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
        recording: RecordingSettings,
    ) -> Self {
        let (prepare_fn, issue_fn) =
            warden_fns(token, worker_id, warden_addr, warden_spiffe, certs);
        Self::with_fns(prepare_fn, issue_fn, registry, session_ended_tx, recording)
    }

    /// Build a handler over injected warden fns (tests stub PrepareSession /
    /// IssueSessionCredential here).
    pub fn with_fns(
        prepare_fn: PrepareFn,
        issue_fn: IssueFn,
        registry: SessionRegistry,
        session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
        recording: RecordingSettings,
    ) -> Self {
        Self {
            prepare_fn,
            issue_fn,
            registry,
            session_ended_tx,
            recording,
            state: None,
            login: None,
            client_channel: None,
            pty: None,
        }
    }

    /// The cached prepared session after a successful auth, if any (tests).
    pub fn session_state(&self) -> Option<&PreparedSession> {
        self.state.as_ref()
    }

    /// Close the client's session channel after a pre-bridge failure (target
    /// unreachable, recording unavailable). Without this the channel is left
    /// half-open — the client already got `channel_success` for its shell — and
    /// the interactive client blocks forever on the session; a raw-mode CLI
    /// can't even Ctrl+C out. Surface the reason, a nonzero exit status, then
    /// EOF+close so the client unblocks and exits.
    async fn fail_client_channel(channel: Channel<Msg>, msg: &str) {
        let _ = channel
            .data_bytes(format!("jumpgate: {msg}\r\n").into_bytes())
            .await;
        let _ = channel.exit_status(1).await;
        let _ = channel.eof().await;
        let _ = channel.close().await;
    }

    /// Start the second hop: dial the target as the requested login with the
    /// session certificate, open a matching channel (pty + shell, or exec), and
    /// bridge it to the client channel until either side closes or a teardown
    /// fires. On completion, report the session ended and drop it from the
    /// registry. `command` is `Some` for exec, `None` for an interactive shell.
    async fn start_hop(&mut self, channel: ChannelId, command: Option<Vec<u8>>) {
        let Some(state) = self.state.as_ref() else {
            tracing::warn!("shell/exec before a successful auth; ignoring");
            return;
        };
        let Some(login) = self.login.clone() else {
            tracing::warn!("shell/exec without a recorded login; ignoring");
            return;
        };
        let Some(client_channel) = self.client_channel.take() else {
            tracing::warn!(
                ?channel,
                "shell/exec without an open session channel; ignoring"
            );
            return;
        };

        // Decide recording BEFORE dialing the target. When warden marked the
        // session `recording_required`, a recorder that cannot be established is a
        // hard refuse: report a failed recording and return without bridging.
        let recorder = if state.recording_required {
            match self.build_recorder(state).await {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(session_id = %state.session_id, error = %e, "recording unavailable; refusing session");
                    let _ = self.session_ended_tx.send(SessionEndReport {
                        session_id: state.session_id.clone(),
                        reason: "recording_unavailable".into(),
                        recording: Some(failed_recording_outcome(
                            &state.recording_object_key,
                            &state.grant_id,
                        )),
                    });
                    Self::fail_client_channel(client_channel, "recording unavailable").await;
                    return;
                }
            }
        } else {
            None
        };

        let (target_handle, target_channel) = match self
            .open_target_channel(state, &login, command)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // A target-identity refusal (HopError::Identity) NEVER reached
                // IssueSessionCredential; the observed identity was already logged
                // in `verify_and_dial_target`. Report the session ended with a
                // stable reason and surface a generic client-safe message — this
                // closes the live-session ledger for THIS session ONLY (the
                // per-session `session_ended_tx.send`) and touches nothing else.
                let reason = e.reason();
                let client_msg = e.client_message();
                tracing::warn!(session_id = %state.session_id, %reason, error = ?e, "target hop refused");
                // Finalize any recorder (abort the upload) and ALWAYS report the
                // session ended — PrepareSession already recorded it in warden's
                // ledger, so a target-fail that skipped the report would orphan the
                // live-session entry. `finalize_recording` yields None for an
                // unrecorded session; the report still fires.
                let recording = finalize_recording(
                    recorder,
                    false,
                    &state.session_id,
                    &state.recording_object_key,
                    &state.grant_id,
                )
                .await;
                let _ = self.session_ended_tx.send(SessionEndReport {
                    session_id: state.session_id.clone(),
                    reason: reason.to_string(),
                    recording,
                });
                Self::fail_client_channel(client_channel, client_msg).await;
                return;
            }
        };

        // Register the live session so a Teardown can force-close it, then bridge.
        let session_id = state.session_id.clone();
        let object_key = state.recording_object_key.clone();
        let grant_id = state.grant_id.clone();
        let handle = self.registry.insert(&session_id);
        let registry = self.registry.clone();
        let ended_tx = self.session_ended_tx.clone();

        // Clone the recorder's tap handle for the bridge; the recorder tuple itself
        // is finalized (finish/fail + report) after the bridge returns.
        let recorder_tap = recorder.as_ref().map(|(h, _, _)| h.clone());

        tokio::spawn(async move {
            // The bridge reports whether it ended on a control-plane teardown
            // (`terminated`), a natural channel close (`closed`), or a recording
            // failure (`recording_failed`). An I/O error while pumping bytes counts
            // as a natural close for reporting.
            let outcome = match proxy::bridge(
                client_channel,
                target_channel,
                handle.cancel,
                recorder_tap,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(e) => {
                    tracing::warn!(session_id = %session_id, error = %e, "channel bridge error");
                    proxy::BridgeOutcome::Closed
                }
            };
            let reason = outcome.reason();

            // Finalize the recording via the shared path: a clean end completes the
            // upload, a recording failure aborts it.
            let recording = finalize_recording(
                recorder,
                outcome != proxy::BridgeOutcome::RecordingFailed,
                &session_id,
                &object_key,
                &grant_id,
            )
            .await;

            // Exactly-once cleanup on every exit path: drop from the registry and
            // report the end to warden once.
            registry.remove(&session_id);
            let _ = ended_tx.send(SessionEndReport {
                session_id: session_id.clone(),
                reason: reason.to_string(),
                recording,
            });
            // The client connection to the target stays up for as long as this
            // task holds `target_handle`; dropping it here closes the second hop.
            drop(target_handle);
            tracing::info!(session_id = %session_id, reason, "session ended");
        });
    }

    /// Build a streaming recorder for `state`: a multipart upload to the recording
    /// bucket under the session's object key, fed by [`crate::record::spawn_recorder`].
    ///
    /// Returns the tap handle, the recorder task's join handle, and the recording's
    /// start timestamp (unix ms). Fails when recording is not configured (no
    /// bucket) or the object store rejects the multipart-upload create — either is
    /// a fail-closed trigger for a `recording_required` session.
    async fn build_recorder(
        &self,
        state: &PreparedSession,
    ) -> anyhow::Result<(
        crate::record::RecorderHandle,
        tokio::task::JoinHandle<crate::record::RecordingReport>,
        i64,
    )> {
        // Header dimensions come from the remembered pty (fallback 80x24).
        let (width, height) = self
            .pty
            .as_ref()
            .map(|p| (p.col_width as u16, p.row_height as u16))
            .filter(|(w, h)| *w != 0 && *h != 0)
            .unwrap_or((80, 24));
        build_recorder(&self.recording, &state.recording_object_key, width, height).await
    }

    /// Verify the target's identity, obtain the credential, and open the matching
    /// channel (applying the remembered pty, then requesting a shell or the given
    /// exec command). Returns the client handle too: it must outlive the channel,
    /// or the connection closes. On any failure the caller aborts the hop (never
    /// bridges); a [`HopError::Identity`] means no credential was ever requested.
    async fn open_target_channel(
        &self,
        state: &PreparedSession,
        login: &str,
        command: Option<Vec<u8>>,
    ) -> Result<
        (
            russh::client::Handle<target::TargetHandler>,
            Channel<russh::client::Msg>,
        ),
        HopError,
    > {
        // Connect → observe → match anchor → issue → authenticate (the enforced
        // verify-before-issue order lives in `verify_and_dial_target`).
        let handle = verify_and_dial_target(state, login, &self.issue_fn).await?;

        // Channel setup is post-auth; a failure here is a target-side connectivity
        // problem (the credential was already released).
        let target_channel = handle
            .channel_open_session()
            .await
            .map_err(|e| HopError::Connect(e.into()))?;

        if let Some(pty) = self.pty.as_ref() {
            target_channel
                .request_pty(
                    false,
                    &pty.term,
                    pty.col_width,
                    pty.row_height,
                    pty.pix_width,
                    pty.pix_height,
                    &pty.modes,
                )
                .await
                .map_err(|e| HopError::Connect(e.into()))?;
        }

        match command {
            Some(cmd) => target_channel
                .exec(true, cmd)
                .await
                .map_err(|e| HopError::Connect(e.into()))?,
            None => target_channel
                .request_shell(true)
                .await
                .map_err(|e| HopError::Connect(e.into()))?,
        }

        Ok((handle, target_channel))
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        match prepare(user, Some(public_key), &self.prepare_fn).await {
            Ok(state) => {
                tracing::info!(
                    session_id = %state.session_id,
                    login = %user,
                    "ssh publickey auth accepted; session prepared (credential deferred to target verify)",
                );
                self.state = Some(state);
                self.login = Some(user.to_string());
                // russh now verifies the client's signature over Kc
                // (proof-of-possession) before the auth actually succeeds.
                Ok(Auth::Accept)
            }
            Err(e) => {
                // Log the reason server-side; the client only sees a generic
                // reject. NEVER accept on error.
                tracing::warn!(login = %user, error = %e, "ssh publickey auth rejected");
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        // Hold the channel until the client requests a shell/exec; that request
        // is the trigger to dial the target and start the bridge.
        self.client_channel = Some(channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Remember the pty so the target request matches the client's terminal.
        self.pty = Some(PtyParams {
            term: term.to_string(),
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes: modes.to_vec(),
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_hop(channel, None).await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.start_hop(channel, Some(data.to_vec())).await;
        Ok(())
    }
}

/// Bind the data-plane mTLS listener and dispatch each accepted gateway
/// connection: TLS-accept (gateway mTLS) → read CONNECT → run the SSH server
/// over the tunnel (publickey auth drives SetupSession).
///
/// `registry` and `session_ended_tx` are the control-plane seam shared with
/// [`crate::control`]: each live session is registered in `registry` (so
/// `Teardown` can force-close it) and reported via `session_ended_tx` when it
/// ends.
///
/// The loop accepts until `shutdown` fires, at which point it stops accepting
/// new connections and force-closes every live session in `registry` (each
/// bridge selects on its handle's `cancel`), then returns.
pub async fn run_dataplane_server(
    config: &Config,
    registry: SessionRegistry,
    session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let cert_pem = fs::read(&config.mesh_cert)
        .with_context(|| format!("read mesh cert {}", config.mesh_cert))?;
    let key_pem =
        fs::read(&config.mesh_key).with_context(|| format!("read mesh key {}", config.mesh_key))?;
    let ca_pem =
        fs::read(&config.mesh_ca).with_context(|| format!("read mesh CA {}", config.mesh_ca))?;

    // The worker's mesh identity, reused for every SetupSession call.
    let mesh_certs = Arc::new(
        MeshClientCerts::from_files(&config.mesh_cert, &config.mesh_key, &config.mesh_ca)
            .context("load worker mesh certs for SetupSession")?,
    );

    let server_config = jumpgate_mesh::tls::server_config_mtls(
        &cert_pem,
        &key_pem,
        &ca_pem,
        &config.gateway_spiffe,
    )
    .context("build data-plane mTLS server config")?;
    let acceptor = TlsAcceptor::from(server_config);

    // Ephemeral SSH host key: the client ignores it (the tunnel is already
    // authenticated by mesh mTLS), so a per-process random key suffices.
    let ssh_config = Arc::new(build_ssh_server_config()?);

    let listener = tokio::net::TcpListener::bind(&config.dataplane_addr)
        .await
        .with_context(|| format!("bind data-plane listener {}", config.dataplane_addr))?;
    tracing::info!(
        addr = %config.dataplane_addr,
        gateway_spiffe = %config.gateway_spiffe,
        "ssh-proxy data-plane mTLS listener ready",
    );

    loop {
        let (tcp, peer) = tokio::select! {
            // Stop accepting on shutdown; force-close every live session so an
            // in-flight bridge tears down instead of being dropped mid-write.
            _ = shutdown.notified() => {
                let live = registry.live_ids();
                tracing::info!(
                    sessions = live.len(),
                    "shutdown signalled; closing live sessions and stopping accept loop",
                );
                for id in live {
                    registry.teardown(&id);
                }
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let ssh_config = ssh_config.clone();
        let mesh_certs = mesh_certs.clone();
        let config = config.clone();
        let registry = registry.clone();
        let session_ended_tx = session_ended_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(
                acceptor,
                ssh_config,
                mesh_certs,
                config,
                registry,
                session_ended_tx,
                tcp,
                peer,
            )
            .await
            {
                tracing::warn!(%peer, error = %e, "data-plane connection failed");
            }
        });
    }
}

/// Serve a minimal plaintext TCP health listener for kubelet probes.
///
/// The data-plane port is mesh mTLS: a bare `tcpSocket` probe against it fails
/// the TLS handshake (and logs a spurious error every probe interval), so probes
/// target this port instead. A `tcpSocket` probe only needs a successful TCP
/// accept, so we accept each connection and immediately drop it — no protocol,
/// no crypto, no framework.
pub async fn run_health_listener(addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind health listener {addr}"))?;
    tracing::info!(%addr, "ssh-proxy health listener ready");
    loop {
        match listener.accept().await {
            // Accept-and-drop: the probe's successful TCP connect is the signal.
            Ok((stream, _peer)) => drop(stream),
            Err(e) => tracing::warn!(error = %e, "health listener accept failed"),
        }
    }
}

/// Build the russh server config with a fresh ephemeral ed25519 host key.
fn build_ssh_server_config() -> anyhow::Result<russh::server::Config> {
    let host_key = PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
        .context("generate ephemeral SSH host key")?;
    Ok(russh::server::Config {
        keys: vec![host_key],
        ..Default::default()
    })
}

/// Per-connection handler: TLS handshake (gateway mTLS), read the CONNECT
/// preamble for the session token, then run the russh SSH server over the tunnel.
#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    acceptor: TlsAcceptor,
    ssh_config: Arc<russh::server::Config>,
    mesh_certs: Arc<MeshClientCerts>,
    config: Config,
    registry: SessionRegistry,
    session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut tls = acceptor
        .accept(tcp)
        .await
        .context("gateway mTLS handshake failed")?;

    let req = jumpgate_mesh::connect::read_connect(&mut tls)
        .await
        .context("read CONNECT preamble")?;

    // Acknowledge the CONNECT before starting the SSH server: the gateway blocks
    // on this `200` response and blind-pipes only afterwards. Without it the
    // gateway reads the SSH banner as an HTTP status line and rejects the tunnel.
    {
        use tokio::io::AsyncWriteExt as _;
        tls.write_all(jumpgate_mesh::connect::response_established())
            .await
            .context("write CONNECT 200 response")?;
        tls.flush().await.context("flush CONNECT 200 response")?;
    }

    let recording = RecordingSettings {
        bucket: config.recording_bucket.clone(),
        endpoint: config.recording_s3_endpoint.clone(),
        region: config.recording_s3_region.clone(),
        part_size: config.recording_part_size,
    };

    // Branch on the preamble: `X-Jumpgate-Terminal: 1` selects the browser-terminal
    // ingress (framed opcode protocol), everything else is the SSH tunnel path.
    if req.terminal {
        // The login is authoritative from the preamble (the browser offers no SSH
        // username); warden's web token also carries it. A terminal CONNECT with
        // no login header is malformed — refuse the connection.
        let login = req
            .login
            .clone()
            .ok_or_else(|| anyhow::anyhow!("terminal CONNECT missing X-Jumpgate-Login header"))?;
        tracing::info!(%peer, authority = %req.authority, %login, "gateway terminal CONNECT received; starting terminal ingress");
        let deps = crate::terminal::TerminalDeps {
            token: req.token,
            login,
            worker_id: config.worker_id.clone(),
            warden_addr: config.warden_mesh_addr.clone(),
            warden_spiffe: config.warden_spiffe.clone(),
            certs: mesh_certs,
            registry,
            session_ended_tx,
            recording,
        };
        crate::terminal::run_terminal(deps, tls).await;
        return Ok(());
    }

    tracing::info!(%peer, authority = %req.authority, "gateway CONNECT received; starting SSH server");

    let handler = SshHandler::new(
        req.token,
        config.worker_id.clone(),
        config.warden_mesh_addr.clone(),
        config.warden_spiffe.clone(),
        mesh_certs,
        registry,
        session_ended_tx,
        recording,
    );

    // Run the SSH server over the already-authenticated tunnel. `run_stream`
    // drives the handshake + auth; the publickey callback performs SetupSession.
    // Session/pty/shell (or exec) requests then drive the target hop + bridge.
    let running = russh::server::run_stream(ssh_config, tls, handler)
        .await
        .context("start SSH server over tunnel")?;
    running
        .await
        .context("SSH server session ended with error")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{certificate, Algorithm};

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    /// The `SHA256:...` fingerprint of a public key, exactly as the anchor store
    /// and the session-time observation both compute it.
    fn fp(pk: &PublicKey) -> String {
        pk.fingerprint(Default::default()).to_string()
    }

    /// A test SSH CA that mints certs over a given public key with given
    /// principals — mirrors warden's `ca.MarshalCert` output (authorized_keys
    /// cert line).
    fn mint_cert(ca: &PrivateKey, subject: &PublicKey, principals: &[&str]) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject,
            now - 60,
            now + 3600,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.key_id("test-session").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        for p in principals {
            builder.valid_principal(*p).unwrap();
        }
        let cert = builder.sign(ca).unwrap();
        cert.to_openssh().unwrap().into_bytes()
    }

    fn anchor(id: &str, kind: &str, fingerprint: &str) -> TrustAnchor {
        TrustAnchor {
            id: id.into(),
            kind: kind.into(),
            algorithm: "ssh-ed25519".into(),
            sha256_fingerprint: fingerprint.into(),
        }
    }

    // --- match_anchor: the constant-time verify-before-issue identity gate -----

    /// An exact `ssh_host_key` anchor whose fingerprint equals the observed host
    /// key matches, selecting that anchor's id and echoing the observed fingerprint.
    #[test]
    fn match_anchor_exact_key_matches() {
        let host = ed25519();
        let observed = host.public_key().clone();
        let anchors = vec![anchor("anchor-1", "ssh_host_key", &fp(&observed))];

        let m = match_anchor(&observed, &anchors).expect("exact fingerprint must match");
        assert_eq!(m.anchor_id, "anchor-1");
        assert_eq!(m.observed_fingerprint, fp(&observed));
    }

    /// A changed key (anchor fingerprint no longer equals the observed key) fails
    /// closed as Unmatched — the MITM / stale-key signal.
    #[test]
    fn match_anchor_changed_key_unmatched() {
        let observed = ed25519().public_key().clone();
        let other = ed25519(); // a different host key was approved
        let anchors = vec![anchor("anchor-1", "ssh_host_key", &fp(other.public_key()))];

        let err = match_anchor(&observed, &anchors).expect_err("changed key must fail closed");
        assert!(matches!(err, IdentityError::Unmatched));
    }

    /// With several `ssh_host_key` anchors, the one whose fingerprint matches is
    /// selected (and its id, not a sibling's, is returned).
    #[test]
    fn match_anchor_multiple_anchors_picks_right() {
        let observed = ed25519().public_key().clone();
        let noise_a = ed25519();
        let noise_b = ed25519();
        let anchors = vec![
            anchor("noise-a", "ssh_host_key", &fp(noise_a.public_key())),
            anchor("the-one", "ssh_host_key", &fp(&observed)),
            anchor("noise-b", "ssh_host_key", &fp(noise_b.public_key())),
        ];

        let m = match_anchor(&observed, &anchors).expect("the matching anchor must be selected");
        assert_eq!(m.anchor_id, "the-one");
    }

    /// A host-CA anchor is refused (fail closed) even when its stored fingerprint
    /// coincides with the observed key: russh 0.62 never surfaces the target's host
    /// CERTIFICATE, so a CA anchor is unverifiable at session time (see probe.rs /
    /// the Task 6 finding). This covers the "host CA principal" path — the session
    /// is refused, never a spoofed CA "match".
    #[test]
    fn match_anchor_host_ca_fails_closed() {
        let observed = ed25519().public_key().clone();
        // Even with a coincidentally-equal fingerprint, a CA anchor must not match.
        let anchors = vec![anchor("ca-1", "ssh_host_ca", &fp(&observed))];

        let err = match_anchor(&observed, &anchors).expect_err("host-CA anchor must fail closed");
        assert!(matches!(err, IdentityError::CaUnsupported));
    }

    /// No anchors at all (e.g. the only approved anchor was revoked/expired, so
    /// warden returned none) fails closed as Unmatched — an unknown target is
    /// refused, never accepted-and-logged.
    #[test]
    fn match_anchor_no_anchors_fails_closed() {
        let observed = ed25519().public_key().clone();
        let err = match_anchor(&observed, &[]).expect_err("no anchors must fail closed");
        assert!(matches!(err, IdentityError::Unmatched));
    }

    // --- build_target_auth: credential validation at issue time ----------------

    #[test]
    fn build_target_auth_accepts_scoped_cert() {
        let ca = ed25519();
        let kw = ed25519();
        let cert = mint_cert(&ca, kw.public_key(), &["deploy@prod.db", "deploy@a1b2c3"]);

        let ta = build_target_auth(TargetCredential::Cert(cert), &kw, "deploy")
            .expect("cert over Kw scoped to deploy must build");
        let TargetAuth::Cert {
            certificate,
            kw: cert_kw,
        } = &ta
        else {
            panic!("ca credential must select the Cert branch");
        };
        assert_eq!(certificate.public_key(), cert_kw.public_key().key_data());
    }

    #[test]
    fn build_target_auth_rejects_cert_not_over_kw() {
        let ca = ed25519();
        let kw = ed25519();
        let other = ed25519(); // cert minted over a DIFFERENT key than Kw
        let cert = mint_cert(&ca, other.public_key(), &["deploy@prod.db"]);

        let err = build_target_auth(TargetCredential::Cert(cert), &kw, "deploy")
            .expect_err("cert not over Kw must be rejected");
        assert!(
            err.contains("not over the worker's session key"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn build_target_auth_rejects_unscoped_principal() {
        let ca = ed25519();
        let kw = ed25519();
        // Cert scoped to deploy; login is root.
        let cert = mint_cert(&ca, kw.public_key(), &["deploy@prod.db"]);

        let err = build_target_auth(TargetCredential::Cert(cert), &kw, "root")
            .expect_err("principals not scoped to login must be rejected");
        assert!(err.contains("not all scoped to login"), "unexpected: {err}");
    }

    #[test]
    fn build_target_auth_rejects_bare_principal() {
        let ca = ed25519();
        let kw = ed25519();
        // A legacy bare-login principal ("deploy", no @scope) is no longer accepted.
        let cert = mint_cert(&ca, kw.public_key(), &["deploy"]);

        let err = build_target_auth(TargetCredential::Cert(cert), &kw, "deploy")
            .expect_err("bare (unscoped) principal must be rejected");
        assert!(err.contains("not all scoped to login"), "unexpected: {err}");
    }

    #[test]
    fn build_target_auth_password_and_key_branches() {
        let kw = ed25519();
        let pw = build_target_auth(
            TargetCredential::Password(Zeroizing::new("hunter2".into())),
            &kw,
            "demo",
        )
        .expect("password credential builds");
        match pw {
            TargetAuth::Password(p) => assert_eq!(p.as_str(), "hunter2"),
            other => panic!("expected Password, got {other:?}"),
        }

        let pem = ed25519()
            .to_openssh(Default::default())
            .unwrap()
            .to_string();
        let key = build_target_auth(
            TargetCredential::Key(Zeroizing::new(pem.clone().into_bytes())),
            &kw,
            "demo",
        )
        .expect("key credential builds");
        match key {
            TargetAuth::Key(b) => assert_eq!(b.as_slice(), pem.as_bytes()),
            other => panic!("expected Key, got {other:?}"),
        }
    }

    // --- prepare (phase 1) + handler wiring ------------------------------------

    fn prepare_stub(anchors: Vec<TrustAnchor>) -> PrepareFn {
        Arc::new(move |_login, _kc_pub| {
            let anchors = anchors.clone();
            Box::pin(async move {
                Ok(PrepareOutcome {
                    session_id: "sess-1".into(),
                    endpoint_revision: 7,
                    target_address: "10.0.0.5:22".into(),
                    grant_id: String::new(),
                    recording_required: false,
                    recording_object_key: String::new(),
                    login: "deploy".into(),
                    anchors,
                })
            })
        })
    }

    fn prepare_err() -> PrepareFn {
        Arc::new(|_login, _kc| Box::pin(async { Err(anyhow::anyhow!("warden unreachable")) }))
    }

    /// An IssueFn that panics if ever called — used to prove that phase 1 (prepare)
    /// and a mismatched identity NEVER reach IssueSessionCredential.
    fn issue_never() -> IssueFn {
        Arc::new(|_sid, _rev, _anchor, _fp, _kw| {
            Box::pin(async { panic!("IssueSessionCredential must not be called on this path") })
        })
    }

    fn test_handler(prepare_fn: PrepareFn, issue_fn: IssueFn) -> SshHandler {
        let (tx, _rx) = mpsc::unbounded_channel();
        SshHandler::with_fns(
            prepare_fn,
            issue_fn,
            SessionRegistry::default(),
            tx,
            RecordingSettings::disabled(),
        )
    }

    /// prepare returns the anchors + a per-session Kw and NO credential; it does
    /// not touch IssueSessionCredential.
    #[tokio::test]
    async fn prepare_carries_anchors_and_no_credential() {
        let kc = ed25519();
        let host = ed25519();
        let anchors = vec![anchor("anchor-1", "ssh_host_key", &fp(host.public_key()))];
        let prep = prepare("deploy", Some(kc.public_key()), &prepare_stub(anchors))
            .await
            .expect("prepare succeeds");

        assert_eq!(prep.session_id, "sess-1");
        assert_eq!(prep.endpoint_revision, 7);
        assert_eq!(prep.target_address, "10.0.0.5:22");
        assert_eq!(prep.anchors.len(), 1);
        assert_eq!(prep.anchors[0].id, "anchor-1");
        // A usable per-session key was generated (its public key serializes).
        assert!(public_key_line(prep.kw.public_key()).is_ok());
    }

    #[tokio::test]
    async fn prepare_rejects_on_prepare_error() {
        let kc = ed25519();
        let err = match prepare("deploy", Some(kc.public_key()), &prepare_err()).await {
            Ok(_) => panic!("PrepareSession error → reject"),
            Err(e) => e,
        };
        assert!(matches!(err, AuthError::Setup(_)));
    }

    #[tokio::test]
    async fn handler_auth_publickey_accepts_and_caches_then_rejects() {
        let kc = ed25519();
        let host = ed25519();
        let anchors = vec![anchor("anchor-1", "ssh_host_key", &fp(host.public_key()))];
        let mut handler = test_handler(prepare_stub(anchors), issue_never());

        let auth = handler
            .auth_publickey("deploy", kc.public_key())
            .await
            .expect("handler auth must not error");
        assert!(matches!(auth, Auth::Accept));
        assert_eq!(
            handler.session_state().expect("state cached").session_id,
            "sess-1"
        );

        // A PrepareSession error rejects (never Accept) and caches no state.
        let mut handler2 = test_handler(prepare_err(), issue_never());
        let auth2 = handler2
            .auth_publickey("deploy", kc.public_key())
            .await
            .expect("handler auth must not error");
        assert!(matches!(auth2, Auth::Reject { .. }));
        assert!(handler2.session_state().is_none());
    }

    // --- recording fail-closed + misc ------------------------------------------

    /// The shared recording finalizer both ingresses route through: a clean end
    /// maps to "completed", a recording failure to "failed", and no recorder
    /// yields no outcome (the unrecorded path — the caller still reports the end).
    #[tokio::test]
    async fn finalize_recording_maps_status_and_none() {
        use crate::record::{spawn_recorder, PartUploader, RecorderConfig};

        struct OkUploader;
        #[async_trait::async_trait]
        impl PartUploader for OkUploader {
            async fn upload_part(&self, _n: i32, _b: Vec<u8>) -> anyhow::Result<()> {
                Ok(())
            }
            async fn complete(&self) -> anyhow::Result<()> {
                Ok(())
            }
            async fn abort(&self) {}
        }
        fn cfg() -> RecorderConfig {
            RecorderConfig {
                part_size: crate::record::MIN_PART_SIZE,
                channel_bound: 16,
            }
        }

        let (h, join) = spawn_recorder(OkUploader, crate::asciicast::Header::new(80, 24, 0), cfg());
        let out = finalize_recording(Some((h, join, 1234)), true, "sess", "obj/key", "grant-1")
            .await
            .expect("a recorder yields an outcome");
        assert_eq!(out.status, "completed");
        assert_eq!(out.object_key, "obj/key");
        assert_eq!(out.grant_id, "grant-1");
        assert_eq!(out.started_at_unix_ms, 1234);

        let (h, join) = spawn_recorder(OkUploader, crate::asciicast::Header::new(80, 24, 0), cfg());
        let out = finalize_recording(Some((h, join, 0)), false, "sess", "obj/key", "grant-1")
            .await
            .expect("a recorder yields an outcome");
        assert_eq!(out.status, "failed");

        assert!(finalize_recording(None, true, "sess", "obj/key", "grant-1")
            .await
            .is_none());
    }

    /// FAIL CLOSED: a `recording_required` session whose worker has no recording
    /// bucket configured cannot build a recorder — `build_recorder` errors, which
    /// `start_hop` turns into a refuse (no bridge, no credential ever issued).
    #[tokio::test]
    async fn build_recorder_fails_closed_without_a_bucket() {
        let handler = test_handler(prepare_stub(vec![]), issue_never());
        let state = PreparedSession {
            session_id: "sess-rec".into(),
            endpoint_revision: 1,
            target_address: "t:22".into(),
            grant_id: String::new(),
            anchors: vec![],
            kw: ed25519(),
            recording_required: true,
            recording_object_key: "recordings/ssh/x.cast".into(),
        };

        let err = match handler.build_recorder(&state).await {
            Ok(_) => panic!("no bucket → build_recorder must fail closed"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("bucket not configured"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn public_key_line_roundtrips() {
        let k = ed25519();
        let pk = k.public_key();
        let line = public_key_line(pk).unwrap();
        let parsed = PublicKey::from_openssh(std::str::from_utf8(&line).unwrap().trim()).unwrap();
        assert_eq!(parsed.key_data(), pk.key_data());
    }
}
