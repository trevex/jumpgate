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
//! 4. the worker requires `login ∈ cert.valid_principals`, that the cert is over
//!    `Kw`, caches the session, and **Accepts** (russh then verifies the client's
//!    signature over `Kc` — proof-of-possession).
//!
//! Any failure — SetupSession error, cert parse failure, cert not over `Kw`,
//! login not in principals — is a hard **Reject**. We NEVER accept on error.
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
use crate::setup::{setup_session, SetupOutcome};
use crate::{proxy, target};
use jumpgate_mesh::tls::MeshClientCerts;

/// A validated, cached session: the outcome of a successful publickey auth.
///
/// `kw` is the per-session private key the target hop presents together with
/// `certificate`. `certificate` is the OpenSSH cert warden minted over
/// `kw.public_key()`.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: String,
    pub target_address: String,
    pub certificate: Certificate,
    pub kw: PrivateKey,
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
    #[error("login {login:?} not in certificate principals {principals:?}")]
    PrincipalNotAllowed {
        login: String,
        principals: Vec<String>,
    },
    #[error("failed to serialize public key: {0}")]
    KeySerialize(String),
}

/// The SetupSession call, injected so [`authorize`] can be tested without a real
/// warden. Takes the OpenSSH public-key bytes for `Kc` and `Kw`; returns
/// warden's outcome or an error (which the caller MUST treat as a hard reject).
pub type SetupFn = Arc<
    dyn Fn(
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
/// Generates a fresh `Kw`, calls SetupSession (via the injected `setup`) with the
/// offered `Kc` + `Kw`, then requires:
/// - SetupSession to succeed,
/// - the returned certificate to parse,
/// - the certificate to be **over `Kw`** (defence against a swapped/confused
///   cert — we only ever present `Kw` on the target hop),
/// - the requested `login` to be in the certificate's `valid_principals`.
///
/// Returns the cached [`SessionState`] on success; ANY failure is an
/// [`AuthError`] and the caller MUST reject. It never returns `Ok` on error.
pub async fn authorize(
    login: &str,
    kc: &PublicKey,
    setup: &SetupFn,
) -> Result<SessionState, AuthError> {
    // 1. Fresh per-session Kw (ed25519). Infallible in practice; treat a keygen
    //    failure as a setup-class error rather than ever accepting.
    let kw = PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
        .map_err(|e| AuthError::Setup(format!("generate Kw: {e}")))?;

    let kc_pub = public_key_line(kc)?;
    let kw_pub = public_key_line(kw.public_key())?;

    // 2. Redeem the token. A transport/authorization error is a hard reject.
    let outcome = setup(kc_pub, kw_pub)
        .await
        .map_err(|e| AuthError::Setup(e.to_string()))?;

    // 3. Parse the cert (authorized_keys cert line, per warden's `ca.MarshalCert`).
    let cert_str = String::from_utf8(outcome.ssh_certificate)
        .map_err(|e| AuthError::CertParse(format!("cert not utf-8: {e}")))?;
    let certificate = Certificate::from_openssh(cert_str.trim())
        .map_err(|e| AuthError::CertParse(e.to_string()))?;

    // 4. The cert MUST certify Kw — the only key we present on the target hop.
    if certificate.public_key() != kw.public_key().key_data() {
        return Err(AuthError::CertNotOverKw);
    }

    // 5. The requested login MUST be one of the cert's principals.
    let principals = certificate.valid_principals();
    if !principals.iter().any(|p| p == login) {
        return Err(AuthError::PrincipalNotAllowed {
            login: login.to_string(),
            principals: principals.to_vec(),
        });
    }

    Ok(SessionState {
        session_id: outcome.session_id,
        target_address: outcome.target_address,
        certificate,
        kw,
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
    session_ended_tx: mpsc::UnboundedSender<(String, String)>,
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
    pub fn new(
        token: String,
        worker_id: String,
        warden_addr: String,
        warden_spiffe: String,
        certs: Arc<MeshClientCerts>,
        registry: SessionRegistry,
        session_ended_tx: mpsc::UnboundedSender<(String, String)>,
    ) -> Self {
        let setup: SetupFn = Arc::new(move |kc_pub, kw_pub| {
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
                    kc_pub,
                    kw_pub,
                )
                .await
            })
        });
        Self::with_setup(setup, registry, session_ended_tx)
    }

    /// Build a handler over an injected SetupSession fn (tests stub warden here).
    pub fn with_setup(
        setup: SetupFn,
        registry: SessionRegistry,
        session_ended_tx: mpsc::UnboundedSender<(String, String)>,
    ) -> Self {
        Self {
            setup,
            registry,
            session_ended_tx,
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

        let (target_handle, target_channel) =
            match self.open_target_channel(state, &login, command).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(session_id = %state.session_id, error = %e, "target hop failed");
                    return;
                }
            };

        // Register the live session so a Teardown can force-close it, then bridge.
        let session_id = state.session_id.clone();
        let handle = self.registry.insert(&session_id);
        let registry = self.registry.clone();
        let ended_tx = self.session_ended_tx.clone();

        tokio::spawn(async move {
            // The bridge reports whether it ended on a control-plane teardown
            // (`terminated`) or a natural channel close (`closed`). An I/O error
            // while pumping bytes counts as a natural close for reporting.
            let reason = match proxy::bridge(client_channel, target_channel, handle.cancel).await {
                Ok(outcome) => outcome.reason(),
                Err(e) => {
                    tracing::warn!(session_id = %session_id, error = %e, "channel bridge error");
                    proxy::BridgeOutcome::Closed.reason()
                }
            };
            // Exactly-once cleanup on every exit path: drop from the registry and
            // report the end to warden once.
            registry.remove(&session_id);
            let _ = ended_tx.send((session_id.clone(), reason.to_string()));
            // The client connection to the target stays up for as long as this
            // task holds `target_handle`; dropping it here closes the second hop.
            drop(target_handle);
            tracing::info!(session_id = %session_id, reason, "session ended");
        });
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
        let handle =
            target::dial_target(&state.target_address, login, &state.kw, &state.certificate)
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
        match authorize(user, public_key, &self.setup).await {
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
    session_ended_tx: mpsc::UnboundedSender<(String, String)>,
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
    session_ended_tx: mpsc::UnboundedSender<(String, String)>,
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

    tracing::info!(%peer, authority = %req.authority, "gateway CONNECT received; starting SSH server");

    let handler = SshHandler::new(
        req.token,
        config.worker_id.clone(),
        config.warden_mesh_addr.clone(),
        config.warden_spiffe.clone(),
        mesh_certs,
        registry,
        session_ended_tx,
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
        SshHandler::with_setup(setup, SessionRegistry::default(), tx)
    }

    /// A stub SetupFn that mints a cert (over the Kw it is handed) with the given
    /// principals, so the principal check runs against a real, parseable cert.
    fn stub_ok(ca: PrivateKey, principals: Vec<String>) -> SetupFn {
        Arc::new(move |_kc_pub, kw_pub| {
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
                    ssh_certificate: cert,
                })
            })
        })
    }

    /// A stub SetupFn that always errors (unreachable warden / bad token / …).
    fn stub_err() -> SetupFn {
        Arc::new(|_kc, _kw| Box::pin(async { Err(anyhow::anyhow!("warden unreachable")) }))
    }

    #[tokio::test]
    async fn accepts_when_login_in_principals_and_caches_state() {
        let ca = ed25519();
        let kc = ed25519();
        let setup = stub_ok(ca, vec!["deploy".into(), "root".into()]);

        let state = authorize("deploy", kc.public_key(), &setup)
            .await
            .expect("deploy is a principal → accept");

        assert_eq!(state.session_id, "sess-1");
        assert_eq!(state.target_address, "10.0.0.5:22");
        // The cached cert MUST be over Kw (the key we present on the hop).
        assert_eq!(
            state.certificate.public_key(),
            state.kw.public_key().key_data()
        );
        assert!(state
            .certificate
            .valid_principals()
            .iter()
            .any(|p| p == "deploy"));
    }

    #[tokio::test]
    async fn handler_auth_publickey_accepts_and_caches_then_rejects() {
        // Exercise the russh Handler wrapper end-to-end (minus the live
        // handshake): accept caches state; a subsequent bad login rejects and
        // does not clobber the cached state with a bogus one.
        let ca = ed25519();
        let kc = ed25519();
        let mut handler = test_handler(stub_ok(ca, vec!["deploy".into()]));

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
    async fn rejects_when_login_not_in_principals() {
        let ca = ed25519();
        let kc = ed25519();
        // Cert only carries "deploy"; the client asks for "root".
        let setup = stub_ok(ca, vec!["deploy".into()]);

        let err = authorize("root", kc.public_key(), &setup)
            .await
            .expect_err("root not in principals → reject");
        assert!(matches!(err, AuthError::PrincipalNotAllowed { .. }));
    }

    #[tokio::test]
    async fn rejects_when_setup_session_errors() {
        let kc = ed25519();
        let err = authorize("deploy", kc.public_key(), &stub_err())
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
        let setup: SetupFn = Arc::new(move |_kc_pub, _kw_pub| {
            let ca = ca.clone();
            Box::pin(async move {
                let other = ed25519();
                let cert = mint_cert(&ca, other.public_key(), &["deploy"]);
                Ok(SetupOutcome {
                    session_id: "sess-x".into(),
                    target_address: "t:22".into(),
                    ssh_certificate: cert,
                })
            })
        });

        let err = authorize("deploy", kc.public_key(), &setup)
            .await
            .expect_err("cert not over Kw → reject");
        assert!(matches!(err, AuthError::CertNotOverKw));
    }

    #[tokio::test]
    async fn rejects_when_cert_unparseable() {
        let kc = ed25519();
        let setup: SetupFn = Arc::new(|_kc, _kw| {
            Box::pin(async {
                Ok(SetupOutcome {
                    session_id: "s".into(),
                    target_address: "t:22".into(),
                    ssh_certificate: b"not a real cert".to_vec(),
                })
            })
        });
        let err = authorize("deploy", kc.public_key(), &setup)
            .await
            .expect_err("garbage cert → reject");
        assert!(matches!(err, AuthError::CertParse(_)));
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
