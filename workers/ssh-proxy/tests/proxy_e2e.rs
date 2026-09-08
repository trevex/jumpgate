//! End-to-end data-path + ordering tests for the ssh-proxy worker.
//!
//! Drives the worker's real russh SSH server (`SshHandler` + `run_stream`) against
//! in-process stubs and asserts the STRICT verify-before-issue ordering:
//!
//!   PrepareSession → target key exchange → local anchor match →
//!   IssueSessionCredential → target user authentication
//!
//! The proof is layered so it is not mock theater:
//! - a shared, ordered event log records `prepare`, `issue`, and `target_auth`
//!   (the last emitted by the stub target the instant it sees a userauth request);
//! - `IssueSessionCredential` is only ever called with the anchor id + the
//!   fingerprint the worker observed on the target's REAL host key — the worker can
//!   obtain that fingerprint only by completing KEX with the target, so a recorded
//!   `issue` event cryptographically implies the key exchange + match preceded it;
//! - on every mismatch path the injected `IssueFn` records nothing and the test
//!   asserts `issue` NEVER appears in the log — no credential is requested for an
//!   unverified target.
//!
//! The TLS + HTTP CONNECT front door is intentionally bypassed (covered by the
//! mesh crate's tests); this drives the russh server directly on a loopback stream
//! exactly as `handle_conn` does after the tunnel is established.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::{certificate, Algorithm, Certificate, PrivateKey, PublicKey};
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{Auth, Handler as ServerHandler, Msg as ServerMsg, Session};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::sync::mpsc;

use ssh_proxy::control::SessionRegistry;
use ssh_proxy::server::{IssueFn, PrepareFn, RecordingSettings, SessionEndReport, SshHandler};
use ssh_proxy::setup::{IssueOutcome, PrepareOutcome, TargetCredential, TrustAnchor};

/// An ordered event log shared across the prepare stub, the issue stub, and the
/// stub target, so a test can assert the exact call order.
type OrderLog = Arc<Mutex<Vec<String>>>;

fn new_log() -> OrderLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn record(log: &OrderLog, event: &str) {
    log.lock().unwrap().push(event.to_string());
}

fn events(log: &OrderLog) -> Vec<String> {
    log.lock().unwrap().clone()
}

/// Fresh ed25519 private key.
fn ed25519() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

/// The `SHA256:...` fingerprint of a public key — the exact form the anchor store
/// and the session-time observation both use.
fn fingerprint(pk: &PublicKey) -> String {
    pk.fingerprint(Default::default()).to_string()
}

fn anchor(id: &str, kind: &str, fp: &str) -> TrustAnchor {
    TrustAnchor {
        id: id.into(),
        kind: kind.into(),
        algorithm: "ssh-ed25519".into(),
        sha256_fingerprint: fp.into(),
    }
}

/// Mint a User certificate over `subject` with `principals`, signed by `ca` —
/// the authorized_keys cert line warden's `ca.MarshalCert` would produce.
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

/// What the injected `IssueFn` observed when (or if) it was called — the anchor id
/// and the observed fingerprint the worker passed. `None` means it was never
/// called (the mismatch invariant).
type IssueSpy = Arc<Mutex<Option<(String, String)>>>;

/// A `PrepareFn` stub: records `prepare`, returns the given anchors + endpoint
/// revision and NO credential (as warden's PrepareSession does).
fn prepare_stub(log: OrderLog, anchors: Vec<TrustAnchor>, target_address: String) -> PrepareFn {
    Arc::new(move |_login, _kc_pub| {
        let log = log.clone();
        let anchors = anchors.clone();
        let target_address = target_address.clone();
        Box::pin(async move {
            record(&log, "prepare");
            Ok(PrepareOutcome {
                session_id: "sess-1".into(),
                endpoint_revision: 42,
                target_address,
                grant_id: String::new(),
                recording_required: false,
                recording_object_key: String::new(),
                login: "deploy".into(),
                anchors,
            })
        })
    })
}

/// An `IssueFn` stub for the SUCCESS path: records `issue` + captures the anchor id
/// and observed fingerprint the worker passed, then mints a cert over exactly the
/// `Kw` it was handed (so the target hop authenticates).
fn issue_ca_stub(log: OrderLog, spy: IssueSpy, ca: PrivateKey, principals: Vec<String>) -> IssueFn {
    Arc::new(
        move |_session_id, _revision, matched_anchor_id, observed_fingerprint, kw_pub| {
            let log = log.clone();
            let spy = spy.clone();
            let ca = ca.clone();
            let principals = principals.clone();
            Box::pin(async move {
                record(&log, "issue");
                *spy.lock().unwrap() = Some((matched_anchor_id, observed_fingerprint));
                let kw_line = String::from_utf8(kw_pub)?;
                let kw = PublicKey::from_openssh(kw_line.trim())?;
                let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
                let cert = mint_cert(&ca, &kw, &refs);
                Ok(IssueOutcome {
                    credential: TargetCredential::Cert(cert.to_openssh().unwrap().into_bytes()),
                })
            })
        },
    )
}

/// An `IssueFn` that MUST NOT be called: it sets `called` and panics. Used on every
/// mismatch path to prove IssueSessionCredential is never reached.
fn issue_forbidden(called: Arc<AtomicBool>) -> IssueFn {
    Arc::new(move |_s, _r, _a, _f, _k| {
        let called = called.clone();
        Box::pin(async move {
            called.store(true, Ordering::SeqCst);
            panic!("IssueSessionCredential must NOT be called for an unverified target");
        })
    })
}

/// A russh server `Config` with a specific host key and a short auth-rejection
/// delay (the default 1s slows the reject test).
fn ssh_server_config(host_key: PrivateKey) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    })
}

// --- Stub target sshd -------------------------------------------------------

/// A minimal russh server that records `target_auth` the moment it sees a userauth
/// request, accepts any auth, and on exec echoes the command back then exits 0; on
/// an interactive shell it echoes stdin.
#[derive(Clone)]
struct TargetStub {
    log: OrderLog,
}

impl ServerHandler for TargetStub {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _u: &str, _k: &PublicKey) -> Result<Auth, Self::Error> {
        record(&self.log, "target_auth");
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _u: &str,
        _c: &Certificate,
    ) -> Result<Auth, Self::Error> {
        record(&self.log, "target_auth");
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
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

/// Bind a stub target sshd on loopback with host key `host_key` and return its
/// address. It serves every accepted connection with [`TargetStub`].
async fn spawn_target_stub(host_key: PrivateKey, log: OrderLog) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let config = ssh_server_config(host_key);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let config = config.clone();
            let log = log.clone();
            tokio::spawn(async move {
                if let Ok(session) =
                    russh::server::run_stream(config, tcp, TargetStub { log }).await
                {
                    let _ = session.await;
                }
            });
        }
    });
    addr
}

// --- Worker under test ------------------------------------------------------

/// Wire the worker's real `SshHandler` (with injected prepare/issue stubs) to one
/// end of a loopback TCP pair and run its russh server; return the other end's
/// address for the synthetic client, plus the shared registry and the SessionEnded
/// receiver.
async fn spawn_worker(
    prepare_fn: PrepareFn,
    issue_fn: IssueFn,
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
        let handler = SshHandler::with_fns(
            prepare_fn,
            issue_fn,
            worker_registry,
            ended_tx,
            RecordingSettings::disabled(),
        );
        let config = ssh_server_config(ed25519());
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

/// Await the next SessionEnded report (with a timeout).
async fn next_ended(rx: &mut mpsc::UnboundedReceiver<SessionEndReport>) -> SessionEndReport {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for SessionEnded")
        .expect("SessionEnded channel closed")
}

// --- Tests ------------------------------------------------------------------

/// HAPPY PATH ORDERING: an exact-key anchor match drives the full strict order —
/// prepare, then (KEX + match, proven by the observed fingerprint reaching issue),
/// then issue, then target auth — and the bytes round-trip.
#[tokio::test]
async fn strict_order_prepare_match_issue_then_target_auth() {
    let ca = ed25519();
    let kc = ed25519();
    let target_host = ed25519();
    let target_fp = fingerprint(target_host.public_key());
    let log = new_log();
    let spy: IssueSpy = Arc::new(Mutex::new(None));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let anchors = vec![anchor("anchor-1", "ssh_host_key", &target_fp)];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    let issue_fn = issue_ca_stub(log.clone(), spy.clone(), ca, vec!["deploy@prod.db".into()]);
    let (worker_addr, _registry, _ended_rx) = spawn_worker(prepare_fn, issue_fn).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(
        ok,
        "publickey auth (PrepareSession) must succeed for 'deploy'"
    );

    let mut channel = handle
        .channel_open_session()
        .await
        .expect("open session channel through worker");
    channel.exec(true, "jumpgate-ok").await.expect("exec");

    let mut out = Vec::new();
    let mut exit_status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            _ => {}
        }
        if exit_status.is_some() && !out.is_empty() {
            break;
        }
    }

    assert_eq!(
        String::from_utf8_lossy(&out),
        "jumpgate-ok",
        "echo must round-trip"
    );
    assert_eq!(exit_status, Some(0));

    // The strict order, observed end to end.
    assert_eq!(
        events(&log),
        vec!["prepare", "issue", "target_auth"],
        "order must be PrepareSession → (KEX+match) → IssueSessionCredential → target auth",
    );
    // Issue was called with the matched anchor AND the fingerprint the worker
    // observed on the target's real host key — proof the KEX + match preceded it.
    let (matched_anchor, observed_fp) = spy.lock().unwrap().clone().expect("issue was called");
    assert_eq!(matched_anchor, "anchor-1");
    assert_eq!(
        observed_fp, target_fp,
        "issue got the observed host-key fingerprint"
    );
}

/// MULTIPLE ANCHORS: several exact-key anchors, only one matching the target — the
/// worker selects the matching anchor's id and issues against it.
#[tokio::test]
async fn multiple_anchors_selects_the_matching_one() {
    let ca = ed25519();
    let kc = ed25519();
    let target_host = ed25519();
    let target_fp = fingerprint(target_host.public_key());
    let log = new_log();
    let spy: IssueSpy = Arc::new(Mutex::new(None));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let anchors = vec![
        anchor(
            "noise-a",
            "ssh_host_key",
            &fingerprint(ed25519().public_key()),
        ),
        anchor("the-one", "ssh_host_key", &target_fp),
        anchor(
            "noise-b",
            "ssh_host_key",
            &fingerprint(ed25519().public_key()),
        ),
    ];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    let issue_fn = issue_ca_stub(log.clone(), spy.clone(), ca, vec!["deploy@prod.db".into()]);
    let (worker_addr, _registry, mut ended_rx) = spawn_worker(prepare_fn, issue_fn).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok);
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "ok").await.expect("exec");
    while channel.wait().await.is_some() {}

    let (matched_anchor, observed_fp) = spy.lock().unwrap().clone().expect("issue was called");
    assert_eq!(
        matched_anchor, "the-one",
        "the matching anchor id must be selected"
    );
    assert_eq!(observed_fp, target_fp);
    let _ = next_ended(&mut ended_rx).await; // session ends cleanly
}

/// CHANGED KEY / MISMATCH: the only anchor's fingerprint no longer matches the
/// target's host key. IssueSessionCredential must NEVER be called and the session
/// is refused with the stable reason.
#[tokio::test]
async fn changed_key_never_issues_credential() {
    let kc = ed25519();
    let target_host = ed25519();
    let approved_but_stale = ed25519(); // a DIFFERENT key was approved
    let log = new_log();
    let issue_called = Arc::new(AtomicBool::new(false));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let anchors = vec![anchor(
        "anchor-1",
        "ssh_host_key",
        &fingerprint(approved_but_stale.public_key()),
    )];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    let (worker_addr, _registry, mut ended_rx) =
        spawn_worker(prepare_fn, issue_forbidden(issue_called.clone())).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(
        ok,
        "PrepareSession still accepts the SSH auth; the refusal is at hop time"
    );
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "ok").await.expect("exec");
    while channel.wait().await.is_some() {}

    let ended = next_ended(&mut ended_rx).await;
    assert_eq!(ended.session_id, "sess-1");
    assert_eq!(
        ended.reason, "target_identity_mismatch",
        "a changed host key must be refused with the stable reason",
    );
    assert!(
        !issue_called.load(Ordering::SeqCst),
        "IssueSessionCredential must not run"
    );
    assert!(
        !events(&log).contains(&"target_auth".to_string()),
        "no target auth on a mismatch"
    );
}

/// HOST-CA ANCHOR: fails closed. russh 0.62 never surfaces the target's host
/// CERTIFICATE (only its plain host KEY), so a CA anchor is unverifiable at session
/// time. Even with a matching stored fingerprint the session is refused and
/// IssueSessionCredential is NEVER called.
#[tokio::test]
async fn host_ca_anchor_fails_closed_never_issues() {
    let kc = ed25519();
    let target_host = ed25519();
    let target_fp = fingerprint(target_host.public_key());
    let log = new_log();
    let issue_called = Arc::new(AtomicBool::new(false));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    // A host-CA anchor, even with a coincidentally-matching fingerprint.
    let anchors = vec![anchor("ca-1", "ssh_host_ca", &target_fp)];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    let (worker_addr, _registry, mut ended_rx) =
        spawn_worker(prepare_fn, issue_forbidden(issue_called.clone())).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok);
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "ok").await.expect("exec");
    while channel.wait().await.is_some() {}

    let ended = next_ended(&mut ended_rx).await;
    assert_eq!(ended.reason, "target_identity_mismatch");
    assert!(
        !issue_called.load(Ordering::SeqCst),
        "a host-CA anchor must not lead to an issue"
    );
}

/// NO ANCHORS: warden returned no active anchors (e.g. the only approved anchor was
/// revoked/expired, which warden filters out — the worker simply sees none). Fail
/// closed; IssueSessionCredential is NEVER called.
#[tokio::test]
async fn no_anchors_fails_closed_never_issues() {
    let kc = ed25519();
    let target_host = ed25519();
    let log = new_log();
    let issue_called = Arc::new(AtomicBool::new(false));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let prepare_fn = prepare_stub(log.clone(), vec![], target_addr);
    let (worker_addr, _registry, mut ended_rx) =
        spawn_worker(prepare_fn, issue_forbidden(issue_called.clone())).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok);
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "ok").await.expect("exec");
    while channel.wait().await.is_some() {}

    let ended = next_ended(&mut ended_rx).await;
    assert_eq!(ended.reason, "target_identity_mismatch");
    assert!(!issue_called.load(Ordering::SeqCst));
}

/// TEARDOWN still tears down a verified, live session (a matching anchor lets the
/// session go live; a control-plane teardown then closes it).
#[tokio::test]
async fn teardown_closes_live_session() {
    let ca = ed25519();
    let kc = ed25519();
    let target_host = ed25519();
    let target_fp = fingerprint(target_host.public_key());
    let log = new_log();
    let spy: IssueSpy = Arc::new(Mutex::new(None));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let anchors = vec![anchor("anchor-1", "ssh_host_key", &target_fp)];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    let issue_fn = issue_ca_stub(log.clone(), spy, ca, vec!["deploy@prod.db".into()]);
    let (worker_addr, registry, mut ended_rx) = spawn_worker(prepare_fn, issue_fn).await;

    let (handle, ok) = client_connect(&worker_addr, "deploy", &kc).await;
    assert!(ok);
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.request_shell(true).await.expect("request shell");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if registry.live_ids().contains(&"sess-1".to_string()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "session never became live"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        registry.teardown("sess-1"),
        "teardown must find the session"
    );

    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = channel.wait().await {
            if matches!(msg, ChannelMsg::Close | ChannelMsg::Eof) {
                return true;
            }
        }
        true
    })
    .await
    .expect("client channel did not close after teardown");
    assert!(closed);

    let ended = next_ended(&mut ended_rx).await;
    assert_eq!(ended.session_id, "sess-1");
    assert_eq!(ended.reason, "terminated");
}

/// LOGIN NOT IN PRINCIPALS: the identity verifies (anchor matches) and a credential
/// is issued, but the released cert's principals are not scoped to the requested
/// login — the credential is rejected at the hop, so the session is refused with a
/// stable reason and never bridges. (The entitlement itself is enforced by warden's
/// PrepareSession; this is the worker-side defence-in-depth check.)
#[tokio::test]
async fn login_not_in_principals_rejected() {
    let ca = ed25519();
    let kc = ed25519();
    let target_host = ed25519();
    let target_fp = fingerprint(target_host.public_key());
    let log = new_log();
    let spy: IssueSpy = Arc::new(Mutex::new(None));

    let target_addr = spawn_target_stub(target_host, log.clone()).await;
    let anchors = vec![anchor("anchor-1", "ssh_host_key", &target_fp)];
    let prepare_fn = prepare_stub(log.clone(), anchors, target_addr);
    // Cert scoped to "deploy"; the client asks for "root".
    let issue_fn = issue_ca_stub(log.clone(), spy, ca, vec!["deploy@prod.db".into()]);
    let (worker_addr, _registry, mut ended_rx) = spawn_worker(prepare_fn, issue_fn).await;

    let (handle, ok) = client_connect(&worker_addr, "root", &kc).await;
    assert!(
        ok,
        "PrepareSession accepts; the cert-principal check is at hop time"
    );
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "ok").await.expect("exec");
    while channel.wait().await.is_some() {}

    let ended = next_ended(&mut ended_rx).await;
    assert_eq!(
        ended.reason, "credential_rejected",
        "a cert whose principals are not scoped to the login must be refused",
    );
    // The target never authenticated: the credential was rejected before auth.
    assert!(!events(&log).contains(&"target_auth".to_string()));
}
