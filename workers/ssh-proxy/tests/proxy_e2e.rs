//! End-to-end data-path test for the ssh-proxy worker.
//!
//! Drives the worker's real russh SSH server (`SshHandler` + `run_stream`)
//! against three in-process stubs and asserts a byte round-trip through the
//! whole auth → session-setup → target-dial → channel-bridge path:
//!
//! - a **test SSH CA** that mints certs over a subject key, mirroring warden's
//!   `ca.MarshalCert` output (authorized_keys cert line),
//! - a **stub SetupFn** injected into the handler in place of the real warden
//!   `SetupSession` call (via `SshHandler::with_setup`): it mints a cert over
//!   the worker's per-session key `Kw` with host-scoped principals
//!   `["deploy@prod.db"]` and points the second hop at the stub target's address,
//! - a **stub target sshd**: a russh server that accepts any publickey/cert
//!   auth and echoes an exec command back before exiting `0` (or echoes stdin
//!   for an interactive shell).
//!
//! The TLS + HTTP CONNECT front door is intentionally bypassed here: the worker
//! runs its russh server on a plain loopback TCP stream. That layer (mesh mTLS,
//! CONNECT preamble) is covered by the mesh crate's own tests; this test targets
//! the SSH auth + proxy path, so it drives the russh server directly on a stream
//! exactly as `handle_conn` does after the tunnel is established.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::{certificate, Algorithm, Certificate, PrivateKey, PublicKey};
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{Auth, Handler as ServerHandler, Msg as ServerMsg, Session};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::sync::mpsc;

use ssh_proxy::control::SessionRegistry;
use ssh_proxy::server::{RecordingSettings, SessionEndReport, SetupFn, SshHandler};
use ssh_proxy::setup::{SetupOutcome, TargetCredential};

/// Fresh ed25519 private key.
fn ed25519() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

/// Mint a User certificate over `subject` with `principals`, signed by `ca`,
/// valid from an hour ago until an hour from now — the authorized_keys cert line
/// warden's `ca.MarshalCert` would produce.
fn mint_cert(ca: &PrivateKey, subject: &PublicKey, principals: &[&str]) -> Certificate {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        subject,
        now - 3600,
        now + 3600,
    )
    .unwrap();
    builder.serial(1).unwrap();
    builder.key_id("e2e-session").unwrap();
    builder.cert_type(certificate::CertType::User).unwrap();
    for p in principals {
        builder.valid_principal(*p).unwrap();
    }
    builder.sign(ca).unwrap()
}

/// A stub SetupFn standing in for warden's `SetupSession`. It optionally checks
/// the offered `Kc` against an expected fingerprint, mints a cert over the `Kw`
/// the handler generated (with the given principals), and returns the stub
/// target's address as the second-hop target.
fn stub_setup(
    ca: PrivateKey,
    principals: Vec<String>,
    target_address: String,
    expect_kc_fp: Option<String>,
) -> SetupFn {
    Arc::new(move |_login, kc_pub, kw_pub| {
        let ca = ca.clone();
        let principals = principals.clone();
        let target_address = target_address.clone();
        let expect_kc_fp = expect_kc_fp.clone();
        Box::pin(async move {
            if let Some(expected) = expect_kc_fp {
                let kc_line = String::from_utf8(kc_pub)?;
                let kc = PublicKey::from_openssh(kc_line.trim())?;
                let got = kc.fingerprint(Default::default()).to_string();
                if got != expected {
                    anyhow::bail!("offered Kc fingerprint {got} != expected {expected}");
                }
            }
            // Mint the cert over exactly the Kw the handler generated.
            let kw_line = String::from_utf8(kw_pub)?;
            let kw = PublicKey::from_openssh(kw_line.trim())?;
            let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
            let cert = mint_cert(&ca, &kw, &refs);
            Ok(SetupOutcome {
                session_id: "sess-1".into(),
                target_address,
                // Empty pin: the test target's host key is ephemeral, so the hop
                // uses accept-and-log (host-key pinning is unit-tested in target.rs).
                target_host_key: String::new(),
                credential: TargetCredential::Cert(cert.to_openssh().unwrap().into_bytes()),
                recording_required: false,
                recording_object_key: String::new(),
            })
        })
    })
}

/// A russh server `Config` with a fresh ephemeral ed25519 host key and a short
/// auth-rejection delay (the default is 1s, which slows the reject test).
fn ssh_server_config() -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        keys: vec![ed25519()],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    })
}

// --- Stub target sshd -------------------------------------------------------

/// A minimal russh server that accepts any auth and, on exec, echoes the command
/// back then exits 0; on an interactive shell it echoes whatever stdin it reads.
#[derive(Clone)]
struct TargetStub;

impl ServerHandler for TargetStub {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _u: &str, _k: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _u: &str,
        _c: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<ServerMsg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // Echo the command back to the client, then close cleanly with status 0.
        session.data(channel, data.to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Interactive-shell echo: bounce stdin straight back.
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

/// Bind a stub target sshd on loopback and return its address. It serves every
/// accepted connection with [`TargetStub`] until the process exits.
async fn spawn_target_stub() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let config = ssh_server_config();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, tcp, TargetStub).await {
                    let _ = session.await;
                }
            });
        }
    });
    addr
}

// --- Worker under test ------------------------------------------------------

/// Wire the worker's real `SshHandler` (with the injected stub setup) to one end
/// of a loopback TCP pair and run its russh server; return the other end's
/// address for the synthetic client to dial, plus the shared registry and the
/// SessionEnded receiver.
async fn spawn_worker(
    setup: SetupFn,
) -> (
    String,
    SessionRegistry,
    mpsc::UnboundedReceiver<SessionEndReport>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let registry = SessionRegistry::default();
    let (ended_tx, ended_rx) = mpsc::unbounded_channel();

    let worker_registry = registry.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let handler = SshHandler::with_setup(
            setup,
            worker_registry,
            ended_tx,
            RecordingSettings::disabled(),
        );
        let config = ssh_server_config();
        if let Ok(session) = russh::server::run_stream(config, tcp, handler).await {
            let _ = session.await;
        }
    });

    (addr, registry, ended_rx)
}

// --- Synthetic client -------------------------------------------------------

/// A russh client that accepts any host key (the worker's ephemeral host key is
/// unauthenticated at the SSH layer — the real tunnel is mesh-authenticated).
struct ClientStub;

impl russh::client::Handler for ClientStub {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _k: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connect to the worker and authenticate with `kc` as `login`. Returns the
/// connected client handle and whether auth succeeded.
async fn client_connect(
    worker_addr: &str,
    login: &str,
    kc: &PrivateKey,
) -> (russh::client::Handle<ClientStub>, bool) {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, worker_addr, ClientStub)
        .await
        .expect("client connect to worker");
    let key = PrivateKeyWithHashAlg::new(Arc::new(kc.clone()), None);
    let result = handle
        .authenticate_publickey(login, key)
        .await
        .expect("client authenticate_publickey call");
    (handle, result.success())
}

// --- Tests ------------------------------------------------------------------

#[tokio::test]
async fn proxy_echoes_through_worker() {
    let ca = ed25519();
    let kc = ed25519();

    let target_addr = spawn_target_stub().await;
    let setup = stub_setup(
        ca,
        vec!["deploy@prod.db".into()],
        target_addr,
        Some(kc.public_key().fingerprint(Default::default()).to_string()),
    );
    let (worker_addr, _registry, _ended_rx) = spawn_worker(setup).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok, "client publickey auth must succeed for login 'deploy'");

    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel through worker");
    channel
        .exec(true, "jumpgate-ok")
        .await
        .expect("exec through worker");

    // Read the echoed command + exit status streamed back from the stub target
    // through the worker's bridge.
    let mut out = Vec::new();
    let mut exit_status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Close | ChannelMsg::Eof => {}
            _ => {}
        }
        if exit_status.is_some() && !out.is_empty() {
            break;
        }
    }

    assert_eq!(
        String::from_utf8_lossy(&out),
        "jumpgate-ok",
        "the target's echoed command must round-trip through the worker",
    );
    assert_eq!(exit_status, Some(0), "target exit status must reach client");
}

#[tokio::test]
async fn teardown_closes_live_session() {
    let ca = ed25519();
    let kc = ed25519();

    let target_addr = spawn_target_stub().await;
    let setup = stub_setup(ca, vec!["deploy@prod.db".into()], target_addr, None);
    let (worker_addr, registry, mut ended_rx) = spawn_worker(setup).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok, "client publickey auth must succeed");

    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel");
    // A shell keeps the session live (no exit) so teardown has something to kill.
    channel
        .request_shell(true)
        .await
        .expect("request shell through worker");

    // Wait for the worker to register the live session before tearing it down.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if registry.live_ids().contains(&"sess-1".to_string()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "session never became live",
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        registry.teardown("sess-1"),
        "teardown must find the session"
    );

    // The client's channel must close promptly on teardown.
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = channel.wait().await {
            if matches!(msg, ChannelMsg::Close | ChannelMsg::Eof) {
                return true;
            }
        }
        // `wait()` returning None also means the channel ended.
        true
    })
    .await
    .expect("client channel did not close after teardown");
    assert!(closed, "client channel must close after teardown");

    // The worker must report the session ended with reason "terminated".
    let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
        .await
        .expect("timed out waiting for SessionEnded")
        .expect("SessionEnded channel closed");
    assert_eq!(ended.session_id, "sess-1");
    assert_eq!(ended.reason, "terminated");
    assert!(ended.recording.is_none());
}

#[tokio::test]
async fn login_not_in_principals_rejected() {
    let ca = ed25519();
    let kc = ed25519();

    let target_addr = spawn_target_stub().await;
    // Cert is scoped to "deploy"; the client asks for "root" — must be rejected.
    let setup = stub_setup(ca, vec!["deploy@prod.db".into()], target_addr, None);
    let (worker_addr, _registry, _ended_rx) = spawn_worker(setup).await;

    let (_handle, ok) = client_connect(&worker_addr, "root", &kc).await;
    assert!(
        !ok,
        "auth for a login whose principals are not all scoped to it must be rejected",
    );
}
