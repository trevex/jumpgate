//! Credential-free SSH host-identity probe tests.
//!
//! Stands up in-process russh servers (and raw TCP stubs) and drives
//! [`ssh_proxy::probe`] against them, asserting the probe:
//!
//! - reaches key exchange and returns canonical host-key evidence (algorithm,
//!   SHA-256 fingerprint, OpenSSH authorized_keys line) matching the server's
//!   configured host key, plus the server identification banner,
//! - never sends a user-auth request (the target's `auth_*` hooks set a flag
//!   that must stay `false`),
//! - rejects a banner larger than `max_banner_bytes` (fail: identity too large),
//! - times out a stalled handshake (fail: connection timeout).
//!
//! Host CERTIFICATE evidence is deferred: russh 0.62 surfaces only plain host
//! keys to the client and cannot serve a host certificate. See the ignored
//! `host_certificate_evidence_deferred` test at the bottom.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::{certificate, Algorithm, Certificate, PrivateKey, PublicKey};
use russh::server::{Auth, Handler as ServerHandler, Msg as ServerMsg, Session};
use russh::Channel;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use ssh_proxy::probe::{self, ProbeFailure};

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    probe_assignment, probe_result, ProbeAssignment, ProbeEvidenceKind, ProbeLimits, ProbeOutcome,
    ProbeProtocol, SshProbeEndpoint,
};

// --- Assignment builders ----------------------------------------------------

/// Generous limits for the happy-path probe (long timeouts, roomy banner).
fn generous_limits() -> ProbeLimits {
    ProbeLimits {
        dns_timeout_ms: 2_000,
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        total_timeout_ms: 10_000,
        max_banner_bytes: 8_192,
        max_frame_bytes: 65_536,
        max_chain_certificates: 8,
        max_certificate_bytes: 16_384,
        max_result_bytes: 262_144,
    }
}

/// Build an SSH probe assignment pointing at `host:port` with the given limits.
fn ssh_assignment(host: &str, port: u16, limits: ProbeLimits) -> ProbeAssignment {
    ProbeAssignment {
        job_id: "job-1".into(),
        asset_id: "asset-1".into(),
        endpoint_revision: 1,
        lease_token: vec![0u8; 32],
        protocol: ProbeProtocol::Ssh as i32,
        lease_expires_at_unix_ms: 1,
        limits: Some(limits),
        endpoint: Some(probe_assignment::Endpoint::Ssh(SshProbeEndpoint {
            host: host.into(),
            port: u32::from(port),
        })),
    }
}

// --- Target sshd stub (auth must never be attempted) ------------------------

/// A russh server that reports on `auth_tx` if any auth hook fires. A
/// credential-free probe must reach KEX and stop, so `auth_tx` must stay empty.
#[derive(Clone)]
struct ProbeTargetStub {
    auth_tx: mpsc::UnboundedSender<String>,
}

impl ServerHandler for ProbeTargetStub {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, u: &str, _k: &PublicKey) -> Result<Auth, Self::Error> {
        let _ = self.auth_tx.send(format!("publickey:{u}"));
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, u: &str, _p: &str) -> Result<Auth, Self::Error> {
        let _ = self.auth_tx.send(format!("password:{u}"));
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_none(&mut self, u: &str) -> Result<Auth, Self::Error> {
        let _ = self.auth_tx.send(format!("none:{u}"));
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
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
}

/// Bind a russh sshd on loopback with `host_key`. Returns (addr, auth_rx,
/// closed_rx): `auth_rx` receives one message per auth attempt (must stay empty
/// for a credential-free probe), and `closed_rx` fires once the server has fully
/// processed the probe's connection and it has closed — so a racing auth request
/// is guaranteed observed on `auth_rx` before the assertion runs.
async fn spawn_probe_target(
    host_key: PrivateKey,
) -> (
    String,
    mpsc::UnboundedReceiver<String>,
    mpsc::UnboundedReceiver<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (auth_tx, auth_rx) = mpsc::unbounded_channel();
    let (closed_tx, closed_rx) = mpsc::unbounded_channel();
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let config = config.clone();
            let handler = ProbeTargetStub {
                auth_tx: auth_tx.clone(),
            };
            let closed_tx = closed_tx.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, tcp, handler).await {
                    // Await the full session: it returns only after the probe drops
                    // its handle and the connection closes, so any auth the peer sent
                    // has already reached the handler above.
                    let _ = session.await;
                }
                let _ = closed_tx.send(());
            });
        }
    });
    (addr, auth_rx, closed_rx)
}

/// Split "127.0.0.1:NNNN" into (host, port).
fn split_addr(addr: &str) -> (String, u16) {
    let (h, p) = addr.rsplit_once(':').unwrap();
    (h.to_string(), p.parse().unwrap())
}

// --- Tests ------------------------------------------------------------------

#[tokio::test]
async fn probe_returns_host_key_evidence_without_authenticating() {
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let expected_fp = host_key
        .public_key()
        .fingerprint(Default::default())
        .to_string();
    let expected_line = host_key.public_key().to_openssh().unwrap();

    let (addr, mut auth_rx, mut closed_rx) = spawn_probe_target(host_key).await;
    let (host, port) = split_addr(&addr);
    let assignment = ssh_assignment(&host, port, generous_limits());

    let obs = probe::run(&assignment)
        .await
        .expect("probe must reach KEX and observe the host key");

    assert_eq!(obs.algorithm, "ssh-ed25519");
    assert_eq!(obs.sha256_fingerprint, expected_fp);
    assert_eq!(obs.openssh_public_line, expected_line);
    assert!(
        obs.banner.starts_with("SSH-2.0-"),
        "banner should be the server identification string, got {:?}",
        obs.banner,
    );
    assert!(
        !obs.resolved_addresses.is_empty(),
        "resolved addresses must be recorded",
    );

    // Deterministic never-authenticate check: wait until the server has fully
    // processed and closed the probe's connection. Only then is `auth_rx`'s state
    // final — a regression that sent a user-auth request would have delivered it
    // to the handler (and thus onto `auth_rx`) before the connection closed.
    tokio::time::timeout(Duration::from_secs(5), closed_rx.recv())
        .await
        .expect("timed out waiting for the server to close the probe connection")
        .expect("server task dropped without signaling close");
    assert!(
        auth_rx.try_recv().is_err(),
        "the probe must never send a user-auth request (saw {:?})",
        auth_rx.try_recv().ok(),
    );

    // The result mapping must carry the same evidence as a Succeeded ProbeResult.
    let result = probe::run_to_result(assignment).await;
    assert_eq!(result.outcome, ProbeOutcome::Succeeded as i32);
    assert_eq!(result.evidence.len(), 1);
    let ev = &result.evidence[0];
    assert_eq!(ev.kind, ProbeEvidenceKind::SshHostKey as i32);
    assert_eq!(ev.sha256_fingerprint, expected_fp);
    assert_eq!(ev.algorithm, "ssh-ed25519");
    match result.protocol_metadata {
        Some(probe_result::ProtocolMetadata::Ssh(md)) => {
            assert!(md.banner.starts_with("SSH-2.0-"));
            // russh does not surface the server's offered host-key algorithm list,
            // so we do not fabricate one (see probe.rs).
            assert!(md.host_key_algorithms.is_empty());
        }
        other => panic!("expected SSH protocol metadata, got {other:?}"),
    }
}

#[tokio::test]
async fn probe_rejects_oversized_banner() {
    // Raw TCP stub that floods a long line with no terminator, exceeding the
    // probe's max_banner_bytes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut tcp, _)) = listener.accept().await {
            let flood = vec![b'A'; 4096];
            let _ = tcp.write_all(&flood).await;
            let _ = tcp.flush().await;
            // Hold the connection open so the client reads the flood.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let (host, port) = split_addr(&addr);
    let mut limits = generous_limits();
    limits.max_banner_bytes = 512;
    let assignment = ssh_assignment(&host, port, limits);

    match probe::run(&assignment).await {
        Err(ProbeFailure::IdentityTooLarge(_)) => {}
        other => panic!("expected IdentityTooLarge for an oversized banner, got {other:?}"),
    }
}

#[tokio::test]
async fn probe_times_out_stalled_handshake() {
    // Raw TCP stub that accepts and then sends nothing: the handshake stalls.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // Keep the socket open but silent for longer than the handshake timeout.
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(tcp);
        }
    });

    let (host, port) = split_addr(&addr);
    let mut limits = generous_limits();
    limits.handshake_timeout_ms = 300;
    let assignment = ssh_assignment(&host, port, limits);

    match probe::run(&assignment).await {
        Err(ProbeFailure::ConnectionTimeout(_)) => {}
        other => panic!("expected ConnectionTimeout for a stalled handshake, got {other:?}"),
    }
}

#[tokio::test]
async fn probe_result_maps_failure_category() {
    // A closed port yields a terminal Failed result (never a panic / no result).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener); // free the port so the connect is refused

    let (host, port) = split_addr(&addr);
    let mut limits = generous_limits();
    limits.connect_timeout_ms = 500;
    let assignment = ssh_assignment(&host, port, limits);

    let result = probe::run_to_result(assignment).await;
    assert_eq!(result.outcome, ProbeOutcome::Failed as i32);
    assert!(
        result.evidence.is_empty(),
        "a failed probe carries no identity evidence",
    );
    assert_ne!(
        result.failure_category, 0,
        "a failure category must be set on a Failed result",
    );
}

/// Host CERTIFICATE evidence (principals/validity for a `*-cert-v01@openssh.com`
/// host key) is DEFERRED: russh 0.62 has no host-certificate support on either
/// side of the connection.
///
/// - The client callback is `check_server_key(&ssh_key::PublicKey)`; russh's
///   `KexProgress::Done.server_host_key` is `Option<PublicKey>`, decoded via
///   `KeyData::decode` (plain key data only, never an `ssh_key::Certificate`).
/// - The default host-key algorithm set (`Preferred::DEFAULT.key`) contains no
///   `*-cert-v01@openssh.com`, so a cert host-key is never even negotiated.
/// - The russh **server** `Config.keys` is `Vec<PrivateKey>` — it cannot serve a
///   host certificate, so this test cannot even stand up a cert-presenting peer.
///
/// Extracting cert principals/validity would require re-implementing KEX
/// host-key negotiation and cert parsing, which the task forbids. We therefore
/// emit only `SSH_HOST_KEY` evidence. This test documents the limitation; the
/// mint below proves the cert machinery exists, only the transport can't carry it.
#[tokio::test]
#[ignore = "russh 0.62 exposes only plain host keys; host-certificate probing is deferred (see doc comment)"]
async fn host_certificate_evidence_deferred() {
    let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        host.public_key(),
        now - 3600,
        now + 3600,
    )
    .unwrap();
    builder.serial(1).unwrap();
    builder.key_id("host-cert").unwrap();
    builder.cert_type(certificate::CertType::Host).unwrap();
    builder.valid_principal("host.example.com").unwrap();
    let cert: Certificate = builder.sign(&ca).unwrap();

    // A host certificate can be minted, but russh's server cannot present it and
    // its client cannot observe it — so no probe path yields cert evidence.
    assert_eq!(cert.cert_type(), certificate::CertType::Host);
}
