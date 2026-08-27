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
use crate::setup::{setup_session, SetupOutcome, TargetCredential};
use crate::{proxy, target};
use jumpgate_mesh::tls::MeshClientCerts;

/// Dial the target and authenticate the second hop by the login's configured
/// credential kind (cert / password / key), returning the connected russh client
/// handle. Shared by the SSH and browser-terminal ingresses so both authenticate
/// the target identically. On error the caller aborts the hop (never bridges).
pub(crate) async fn dial_target_by_auth(
    target_address: &str,
    host_key_pin: &str,
    login: &str,
    target_auth: &TargetAuth,
) -> anyhow::Result<russh::client::Handle<target::TargetHandler>> {
    match target_auth {
        TargetAuth::Cert { certificate, kw } => {
            target::dial_target(target_address, host_key_pin, login, kw, certificate).await
        }
        TargetAuth::Password(password) => {
            target::authenticate_password(target_address, host_key_pin, login, password).await
        }
        TargetAuth::Key(pem) => {
            target::authenticate_publickey(target_address, host_key_pin, login, pem).await
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
/// `Password`/`Key` carry warden-injected secrets that never touch the client.
#[derive(Debug)]
pub enum TargetAuth {
    // Boxed: the cert + key make this variant far larger than the secret ones.
    Cert {
        certificate: Box<Certificate>,
        kw: Box<PrivateKey>,
    },
    Password(String),
    Key(Vec<u8>),
}

/// A validated, cached session: the outcome of a successful publickey auth.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: String,
    pub target_address: String,
    /// The asset's configured target host-key pin (OpenSSH authorized_keys line),
    /// or empty for no pin. Enforced on the target hop (fail closed on mismatch).
    pub target_host_key: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Echoed back in the recording report for session attribution.
    pub grant_id: String,
    /// How the worker authenticates the target hop for this session.
    pub target_auth: TargetAuth,
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

/// Why an auth attempt was rejected. All variants map to `Auth::Reject` — the
/// distinction exists for logging/tests only, never to leak to the client.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("SetupSession failed: {0}")]
    Setup(String),
    #[error("certificate parse failed: {0}")]
    CertParse(String),
    #[error("certificate is not over the worker's per-session key Kw")]
    CertNotOverKw,
    #[error("certificate principals {principals:?} are not all scoped to login {login:?}")]
    PrincipalNotForLogin {
        login: String,
        principals: Vec<String>,
    },
    #[error("failed to serialize public key: {0}")]
    KeySerialize(String),
}

/// The SetupSession call, injected so [`authorize`] can be tested without a real
/// warden. Takes the requested `login` plus the OpenSSH public-key bytes for `Kc`
/// and `Kw`; returns warden's outcome or an error (which the caller MUST treat as
/// a hard reject).
pub type SetupFn = Arc<
    dyn Fn(
            String,  // login (the client's requested SSH username)
            Vec<u8>, // kc_pub (authorized_keys line)
            Vec<u8>, // kw_pub (authorized_keys line)
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<SetupOutcome>> + Send>>
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

/// The security-critical publickey-auth decision, isolated from russh.
///
/// Generates a fresh `Kw` and calls SetupSession (via the injected `setup`) with
/// the requested `login` + the offered `Kc` + `Kw`. warden returns a
/// discriminated credential keyed on the login's configured kind, and the worker
/// branches:
/// - `Cert` (ca): the returned certificate must parse, be **over `Kw`** (defence
///   against a swapped/confused cert — we only ever present `Kw` on the target
///   hop), and have every principal of the form `<login>@<scope>` (host-scoped).
///   The host binding is enforced by the target's `AuthorizedPrincipalsFile`.
///   `Kw` + the cert are cached.
/// - `Password`/`Key`: `Kw` is discarded; the plain secret is cached for the
///   target hop. warden already enforced the login entitlement.
///
/// The worker still generates and offers `Kw` in every case (the proto requires
/// `target_public_key`); only its *use* is gated to the `Cert` path.
///
/// `kc` is the client's ephemeral key for the SSH ingress (proof-of-possession
/// binds it via the token's `cnf`). The browser-terminal ingress has no client
/// key: it passes `None`, which sends an EMPTY client key — warden's `mode=web`
/// tokens skip the `cnf` proof and take the login from the ticket. Every other
/// check (SetupSession authorization, cert-over-Kw, host-scoped principals) is
/// identical for both ingresses.
///
/// Returns the cached [`SessionState`] on success; ANY failure is an
/// [`AuthError`] and the caller MUST reject. It never returns `Ok` on error.
pub async fn authorize(
    login: &str,
    kc: Option<&PublicKey>,
    setup: &SetupFn,
) -> Result<SessionState, AuthError> {
    // 1. Fresh per-session Kw (ed25519). Infallible in practice; treat a keygen
    //    failure as a setup-class error rather than ever accepting.
    let kw = PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
        .map_err(|e| AuthError::Setup(format!("generate Kw: {e}")))?;

    // An SSH-ingress client offers its Kc; the browser terminal has none, so we
    // send an empty client key (warden's web tokens carry no `cnf` to prove).
    let kc_pub = match kc {
        Some(kc) => public_key_line(kc)?,
        None => Vec::new(),
    };
    let kw_pub = public_key_line(kw.public_key())?;

    // 2. Redeem the token. A transport/authorization error is a hard reject.
    let outcome = setup(login.to_string(), kc_pub, kw_pub)
        .await
        .map_err(|e| AuthError::Setup(e.to_string()))?;

    // 3. Branch on the credential kind warden returned.
    let target_auth = match outcome.credential {
        TargetCredential::Cert(cert_bytes) => {
            // Parse the cert (authorized_keys cert line, per warden's `ca.MarshalCert`).
            let cert_str = String::from_utf8(cert_bytes)
                .map_err(|e| AuthError::CertParse(format!("cert not utf-8: {e}")))?;
            let certificate = Certificate::from_openssh(cert_str.trim())
                .map_err(|e| AuthError::CertParse(e.to_string()))?;

            // The cert MUST certify Kw — the only key we present on the target hop.
            if certificate.public_key() != kw.public_key().key_data() {
                return Err(AuthError::CertNotOverKw);
            }

            // Every principal MUST be host-scoped to the requested login
            // (`<login>@<scope>`), binding the cert to the login the worker
            // authenticates as. The *host* binding (which asset) is enforced by the
            // target's AuthorizedPrincipalsFile — the worker need not know the path/id.
            // (Prefix-only by design: the worker binds login, the target's
            // AuthorizedPrincipalsFile enforces the exact <login>@<scope> match.)
            let principals = certificate.valid_principals();
            let login_prefix = format!("{login}@");
            if principals.is_empty() || !principals.iter().all(|p| p.starts_with(&login_prefix)) {
                return Err(AuthError::PrincipalNotForLogin {
                    login: login.to_string(),
                    principals: principals.to_vec(),
                });
            }

            TargetAuth::Cert {
                certificate: Box::new(certificate),
                kw: Box::new(kw),
            }
        }
        // Password/key: Kw is not used; warden already enforced the entitlement.
        TargetCredential::Password(password) => TargetAuth::Password(password),
        TargetCredential::Key(pem) => TargetAuth::Key(pem),
    };

    Ok(SessionState {
        session_id: outcome.session_id,
        target_address: outcome.target_address,
        target_host_key: outcome.target_host_key,
        grant_id: outcome.grant_id,
        target_auth,
        recording_required: outcome.recording_required,
        recording_object_key: outcome.recording_object_key,
    })
}

/// Per-connection SSH server handler. Holds the CONNECT token + shared deps, and
/// (after a successful auth) the cached [`SessionState`], the requested login,
/// the accepted client channel, and any pty parameters — everything the
/// shell/exec trigger needs to dial the target and start the bridge.
pub struct SshHandler {
    setup: SetupFn,
    /// Force-close registry + finished-session reporter, shared with the control
    /// plane so warden can tear a live session down and learn when it ends.
    registry: SessionRegistry,
    session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
    /// Recording store settings, used to build the per-session uploader.
    recording: RecordingSettings,
    /// Cached after a successful publickey auth; consumed by the target hop.
    state: Option<SessionState>,
    /// The login the client authenticated as (a cert principal).
    login: Option<String>,
    /// The client's session channel, accepted in `channel_open_session`.
    client_channel: Option<Channel<Msg>>,
    /// Remembered pty request, replayed on the target before shell/exec.
    pty: Option<PtyParams>,
}

impl SshHandler {
    /// Build a handler that redeems `token` via a real SetupSession call to
    /// `warden_addr` (pinned to `warden_spiffe`) as `worker_id`.
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
        let setup: SetupFn = Arc::new(move |login, kc_pub, kw_pub| {
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
        });
        Self::with_setup(setup, registry, session_ended_tx, recording)
    }

    /// Build a handler over an injected SetupSession fn (tests stub warden here).
    pub fn with_setup(
        setup: SetupFn,
        registry: SessionRegistry,
        session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
        recording: RecordingSettings,
    ) -> Self {
        Self {
            setup,
            registry,
            session_ended_tx,
            recording,
            state: None,
            login: None,
            client_channel: None,
            pty: None,
        }
    }

    /// The cached session after a successful auth, if any (tests).
    pub fn session_state(&self) -> Option<&SessionState> {
        self.state.as_ref()
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
                        recording: Some(RecordingOutcome {
                            object_key: state.recording_object_key.clone(),
                            size_bytes: 0,
                            sha256: String::new(),
                            started_at_unix_ms: 0,
                            ended_at_unix_ms: 0,
                            status: "failed".into(),
                            grant_id: state.grant_id.clone(),
                        }),
                    });
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
                tracing::warn!(session_id = %state.session_id, error = %e, "target hop failed");
                // A recorder may already have been spun up; finalize it and
                // report the failed recording. The invariant is that once a
                // recorder exists for a required session, EVERY exit path both
                // finalizes the upload and sends exactly one SessionEndReport.
                let recording = if let Some((handle, join, started_ms)) = recorder {
                    // Abort the multipart upload so nothing dangles, then await
                    // the recorder task for an accurate (failed) report.
                    handle.fail().await;
                    let report = join.await.unwrap_or_else(|e| {
                            tracing::warn!(session_id = %state.session_id, error = %e, "recorder task join failed");
                            crate::record::RecordingReport {
                                size_bytes: 0,
                                sha256_hex: String::new(),
                                status: crate::record::RecordStatus::Failed,
                            }
                        });
                    Some(RecordingOutcome {
                        object_key: state.recording_object_key.clone(),
                        size_bytes: report.size_bytes,
                        sha256: report.sha256_hex,
                        started_at_unix_ms: started_ms,
                        ended_at_unix_ms: unix_millis_now(),
                        status: "failed".into(),
                        grant_id: state.grant_id.clone(),
                    })
                } else {
                    // Unrecorded session: keep the prior behavior — no report.
                    None
                };
                if recording.is_some() {
                    let _ = self.session_ended_tx.send(SessionEndReport {
                        session_id: state.session_id.clone(),
                        reason: "target_unavailable".into(),
                        recording,
                    });
                }
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

        tokio::spawn(async move {
            // Split the recorder into the tap handle (fed into the bridge) and the
            // join handle + start timestamp used to finalize the recording report.
            let (rec_handle, rec_join, started_ms) = match recorder {
                Some((h, j, s)) => (Some(h), Some(j), s),
                None => (None, None, 0),
            };

            // The bridge reports whether it ended on a control-plane teardown
            // (`terminated`), a natural channel close (`closed`), or a recording
            // failure (`recording_failed`). An I/O error while pumping bytes counts
            // as a natural close for reporting.
            let outcome = match proxy::bridge(
                client_channel,
                target_channel,
                handle.cancel,
                rec_handle.clone(),
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

            // Finalize the recording: a clean end completes the upload; a recording
            // failure aborts it. Await the recorder task for the final report.
            let recording = if let (Some(h), Some(join)) = (rec_handle, rec_join) {
                if outcome == proxy::BridgeOutcome::RecordingFailed {
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
                let ended_ms = unix_millis_now();
                let status = match report.status {
                    crate::record::RecordStatus::Completed => "completed",
                    crate::record::RecordStatus::Failed => "failed",
                };
                Some(RecordingOutcome {
                    object_key,
                    size_bytes: report.size_bytes,
                    sha256: report.sha256_hex,
                    started_at_unix_ms: started_ms,
                    ended_at_unix_ms: ended_ms,
                    status: status.into(),
                    grant_id,
                })
            } else {
                None
            };

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
        state: &SessionState,
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

    /// Dial the target and open the matching channel (applying the remembered
    /// pty, then requesting a shell or the given exec command). Returns the
    /// client handle too: it must outlive the channel, or the connection closes.
    async fn open_target_channel(
        &self,
        state: &SessionState,
        login: &str,
        command: Option<Vec<u8>>,
    ) -> anyhow::Result<(
        russh::client::Handle<target::TargetHandler>,
        Channel<russh::client::Msg>,
    )> {
        // Authenticate the target hop by the login's configured kind. On error,
        // the caller aborts the hop (never bridges).
        let handle = dial_target_by_auth(
            &state.target_address,
            &state.target_host_key,
            login,
            &state.target_auth,
        )
        .await?;

        let target_channel = handle.channel_open_session().await?;

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
                .await?;
        }

        match command {
            Some(cmd) => target_channel.exec(true, cmd).await?,
            None => target_channel.request_shell(true).await?,
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
        match authorize(user, Some(public_key), &self.setup).await {
            Ok(state) => {
                tracing::info!(
                    session_id = %state.session_id,
                    login = %user,
                    "ssh publickey auth accepted; session set up",
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

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    /// A handler over a stubbed setup with a throwaway registry + ended channel
    /// (the auth path under test touches neither).
    fn test_handler(setup: SetupFn) -> SshHandler {
        let (tx, _rx) = mpsc::unbounded_channel();
        SshHandler::with_setup(
            setup,
            SessionRegistry::default(),
            tx,
            RecordingSettings::disabled(),
        )
    }

    /// A stub SetupFn that mints a cert (over the Kw it is handed) with the given
    /// principals, so the principal check runs against a real, parseable cert.
    fn stub_ok(ca: PrivateKey, principals: Vec<String>) -> SetupFn {
        Arc::new(move |_login, _kc_pub, kw_pub| {
            let ca = ca.clone();
            let principals = principals.clone();
            Box::pin(async move {
                // Recover Kw's public key from the authorized_keys line the
                // handler sent, and mint a cert over exactly that key.
                let kw_line = String::from_utf8(kw_pub).unwrap();
                let kw_pk = PublicKey::from_openssh(kw_line.trim()).unwrap();
                let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
                let cert = mint_cert(&ca, &kw_pk, &refs);
                Ok(SetupOutcome {
                    session_id: "sess-1".into(),
                    target_address: "10.0.0.5:22".into(),
                    target_host_key: String::new(),
                    grant_id: String::new(),
                    credential: TargetCredential::Cert(cert),
                    recording_required: false,
                    recording_object_key: String::new(),
                })
            })
        })
    }

    /// A stub SetupFn that returns a plain `Password` credential (kind `password`).
    fn stub_password(password: &str) -> SetupFn {
        let password = password.to_string();
        Arc::new(move |_login, _kc_pub, _kw_pub| {
            let password = password.clone();
            Box::pin(async move {
                Ok(SetupOutcome {
                    session_id: "sess-pw".into(),
                    target_address: "10.0.0.6:22".into(),
                    target_host_key: String::new(),
                    grant_id: String::new(),
                    credential: TargetCredential::Password(password),
                    recording_required: false,
                    recording_object_key: String::new(),
                })
            })
        })
    }

    /// A stub SetupFn that returns a plain `Key` credential (kind `key`) carrying
    /// the given OpenSSH private-key PEM bytes.
    fn stub_key(pem: Vec<u8>) -> SetupFn {
        Arc::new(move |_login, _kc_pub, _kw_pub| {
            let pem = pem.clone();
            Box::pin(async move {
                Ok(SetupOutcome {
                    session_id: "sess-key".into(),
                    target_address: "10.0.0.7:22".into(),
                    target_host_key: String::new(),
                    grant_id: String::new(),
                    credential: TargetCredential::Key(pem),
                    recording_required: false,
                    recording_object_key: String::new(),
                })
            })
        })
    }

    /// A stub SetupFn that always errors (unreachable warden / bad token / …).
    fn stub_err() -> SetupFn {
        Arc::new(|_login, _kc, _kw| Box::pin(async { Err(anyhow::anyhow!("warden unreachable")) }))
    }

    #[tokio::test]
    async fn accepts_when_all_principals_scoped_to_login() {
        let ca = ed25519();
        let kc = ed25519();
        // Warden mints [deploy@<path>, deploy@<id>]; both are scoped to `deploy`.
        let setup = stub_ok(ca, vec!["deploy@prod.db".into(), "deploy@a1b2c3".into()]);

        let state = authorize("deploy", Some(kc.public_key()), &setup)
            .await
            .expect("all principals scoped to deploy → accept");

        assert_eq!(state.session_id, "sess-1");
        assert_eq!(state.target_address, "10.0.0.5:22");
        let TargetAuth::Cert { certificate, kw } = &state.target_auth else {
            panic!("ca credential must select the Cert target-auth branch");
        };
        assert_eq!(certificate.public_key(), kw.public_key().key_data());
        assert!(certificate
            .valid_principals()
            .iter()
            .all(|p| p.starts_with("deploy@")));
    }

    #[tokio::test]
    async fn password_credential_selects_password_branch() {
        // A `password` credential caches the plain secret for the target hop and
        // skips Kw/cert entirely (no principal check applies).
        let kc = ed25519();
        let setup = stub_password("hunter2");

        let state = authorize("demo", Some(kc.public_key()), &setup)
            .await
            .expect("password credential → accept");

        assert_eq!(state.session_id, "sess-pw");
        assert_eq!(state.target_address, "10.0.0.6:22");
        match &state.target_auth {
            TargetAuth::Password(pw) => assert_eq!(pw, "hunter2"),
            other => panic!("expected Password branch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn key_credential_selects_key_branch() {
        // A `key` credential caches the private-key PEM bytes for the target hop.
        let kc = ed25519();
        let pem = ed25519()
            .to_openssh(Default::default())
            .unwrap()
            .to_string();
        let setup = stub_key(pem.clone().into_bytes());

        let state = authorize("demo", Some(kc.public_key()), &setup)
            .await
            .expect("key credential → accept");

        assert_eq!(state.session_id, "sess-key");
        assert_eq!(state.target_address, "10.0.0.7:22");
        match &state.target_auth {
            TargetAuth::Key(bytes) => assert_eq!(bytes, pem.as_bytes()),
            other => panic!("expected Key branch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handler_auth_publickey_accepts_and_caches_then_rejects() {
        // Exercise the russh Handler wrapper end-to-end (minus the live
        // handshake): accept caches state; a subsequent bad login rejects and
        // does not clobber the cached state with a bogus one.
        let ca = ed25519();
        let kc = ed25519();
        let mut handler = test_handler(stub_ok(ca, vec!["deploy@prod.db".into()]));

        let auth = handler
            .auth_publickey("deploy", kc.public_key())
            .await
            .expect("handler auth must not error");
        assert!(matches!(auth, Auth::Accept));
        assert_eq!(
            handler.session_state().expect("state cached").session_id,
            "sess-1"
        );

        // A rejected attempt yields Auth::Reject (never Accept) and leaves no
        // new state cached beyond what a rejection would set (None).
        let mut handler2 = test_handler(stub_err());
        let auth2 = handler2
            .auth_publickey("deploy", kc.public_key())
            .await
            .expect("handler auth must not error");
        assert!(matches!(auth2, Auth::Reject { .. }));
        assert!(handler2.session_state().is_none());
    }

    #[tokio::test]
    async fn rejects_when_principal_not_scoped_to_login() {
        let ca = ed25519();
        let kc = ed25519();
        // Cert is scoped to "deploy"; the client asks for "root".
        let setup = stub_ok(ca, vec!["deploy@prod.db".into()]);

        let err = authorize("root", Some(kc.public_key()), &setup)
            .await
            .expect_err("principals not scoped to root → reject");
        assert!(matches!(err, AuthError::PrincipalNotForLogin { .. }));
    }

    #[tokio::test]
    async fn rejects_bare_login_principal() {
        let ca = ed25519();
        let kc = ed25519();
        // A legacy bare-login cert ("deploy", no @scope) must no longer be accepted.
        let setup = stub_ok(ca, vec!["deploy".into()]);

        let err = authorize("deploy", Some(kc.public_key()), &setup)
            .await
            .expect_err("bare (unscoped) principal → reject");
        assert!(matches!(err, AuthError::PrincipalNotForLogin { .. }));
    }

    #[tokio::test]
    async fn rejects_when_setup_session_errors() {
        let kc = ed25519();
        let err = authorize("deploy", Some(kc.public_key()), &stub_err())
            .await
            .expect_err("SetupSession error → reject");
        assert!(matches!(err, AuthError::Setup(_)));
    }

    #[tokio::test]
    async fn rejects_when_cert_is_not_over_kw() {
        // Stub mints a cert over a DIFFERENT key than the Kw it was handed —
        // the cert-over-Kw invariant must catch it.
        let ca = ed25519();
        let kc = ed25519();
        let setup: SetupFn = Arc::new(move |_login, _kc_pub, _kw_pub| {
            let ca = ca.clone();
            Box::pin(async move {
                let other = ed25519();
                let cert = mint_cert(&ca, other.public_key(), &["deploy@prod.db"]);
                Ok(SetupOutcome {
                    session_id: "sess-x".into(),
                    target_address: "t:22".into(),
                    target_host_key: String::new(),
                    grant_id: String::new(),
                    credential: TargetCredential::Cert(cert),
                    recording_required: false,
                    recording_object_key: String::new(),
                })
            })
        });

        let err = authorize("deploy", Some(kc.public_key()), &setup)
            .await
            .expect_err("cert not over Kw → reject");
        assert!(matches!(err, AuthError::CertNotOverKw));
    }

    #[tokio::test]
    async fn rejects_when_cert_unparseable() {
        let kc = ed25519();
        let setup: SetupFn = Arc::new(|_login, _kc, _kw| {
            Box::pin(async {
                Ok(SetupOutcome {
                    session_id: "s".into(),
                    target_address: "t:22".into(),
                    target_host_key: String::new(),
                    grant_id: String::new(),
                    credential: TargetCredential::Cert(b"not a real cert".to_vec()),
                    recording_required: false,
                    recording_object_key: String::new(),
                })
            })
        });
        let err = authorize("deploy", Some(kc.public_key()), &setup)
            .await
            .expect_err("garbage cert → reject");
        assert!(matches!(err, AuthError::CertParse(_)));
    }

    /// FAIL CLOSED: a `recording_required` session whose worker has no recording
    /// bucket configured must not be able to build a recorder — `build_recorder`
    /// errors, and `start_hop` turns that into a refuse (no bridge).
    #[tokio::test]
    async fn build_recorder_fails_closed_without_a_bucket() {
        let handler = test_handler(stub_ok(ed25519(), vec!["deploy@prod.db".into()]));
        // A minimal required-recording session state (the cert/kw are unused by
        // build_recorder; only the object key + the disabled bucket matter).
        let kw = ed25519();
        let ca = ed25519();
        let cert_bytes = mint_cert(&ca, kw.public_key(), &["deploy@prod.db"]);
        let cert =
            Certificate::from_openssh(std::str::from_utf8(&cert_bytes).unwrap().trim()).unwrap();
        let state = SessionState {
            session_id: "sess-rec".into(),
            target_address: "t:22".into(),
            target_host_key: String::new(),
            grant_id: String::new(),
            target_auth: TargetAuth::Cert {
                certificate: Box::new(cert),
                kw: Box::new(kw),
            },
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
