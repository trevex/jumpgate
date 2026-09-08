//! Credential-free RDP TLS identity probe + verify-before-issue boundary tests.
//!
//! Stands up in-process TLS RDP-ish targets (a TCP listener that answers the X.224
//! Connection Request with a Connection Confirm, then completes a rustls server
//! handshake presenting a configured certificate chain) and drives
//! [`rdp_proxy::probe`] + [`rdp_proxy::bridge`] against them, asserting:
//!
//! - the probe reaches the TLS handshake and returns the presented chain +
//!   canonical leaf fingerprint + TLS evidence, without sending any MCS/Client Info;
//! - `match_identity` accepts a correct leaf pin / correct CA+name (incl. CA
//!   rotation) and rejects a wrong pin / wrong name / expired leaf / wrong CA;
//! - a negotiation downgrade, a stalled handshake, and oversized certs each fail
//!   with the right category;
//! - **the bridge NEVER requests a credential (never reaches the Client Info
//!   injection path) unless the observed target identity matched an approved
//!   anchor** — proven by a spy `issue` closure that flags if it is ever reached.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ironrdp_core::encode_vec;
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, RequestFlags, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::RDCleanPathPdu;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rdp_proxy::probe::{self, ProbeFailure, SessionAnchor};

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    probe_assignment, probe_result, ProbeAssignment, ProbeEvidenceKind, ProbeLimits, ProbeOutcome,
    ProbeProtocol, RdpProbeEndpoint,
};

// --- crypto / cert fixtures -------------------------------------------------

fn install_provider() {
    // Idempotent across tests; the probe uses builder_with_provider so this is only
    // needed for the in-process rustls SERVER configs below.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A self-signed leaf presenting `name`. Returns (chain=[leaf], key, leaf_fingerprint).
fn self_signed(name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String) {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let fp = probe::fingerprint_der(der.as_ref());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (vec![der], key, fp)
}

/// A CA + a leaf signed by it presenting `name`. When `expired`, the leaf's
/// validity window is entirely in the past. Returns (chain=[leaf, ca], leaf key,
/// ca_pem, ca_fingerprint).
fn ca_and_leaf(
    name: &str,
    expired: bool,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca_cert.der().clone();
    let ca_fp = probe::fingerprint_der(ca_der.as_ref());
    let ca_pem = ca_cert.pem();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![name.to_string()]).unwrap();
    if expired {
        leaf_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (vec![leaf_cert.der().clone(), ca_der], key, ca_pem, ca_fp)
}

fn server_config(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    )
}

// --- RDP-ish TLS target fixture ---------------------------------------------

#[derive(Clone, Copy)]
enum TargetMode {
    /// Answer the X.224 CR with a CC (TLS accepted), then complete the TLS
    /// handshake and read to EOF.
    Normal,
    /// Answer the X.224 CR with a negotiation FAILURE (refuse TLS).
    Downgrade,
    /// Accept the TCP connection but send nothing (stall the handshake).
    Silent,
}

/// Bind a loopback RDP-ish TLS target. Returns "host:port".
async fn spawn_target(
    mode: TargetMode,
    cfg: Option<Arc<rustls::ServerConfig>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let cfg = cfg.clone();
            tokio::spawn(async move {
                match mode {
                    TargetMode::Silent => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    TargetMode::Downgrade => {
                        let _ = read_x224(&mut tcp).await;
                        let cc = encode_vec(&X224(ConnectionConfirm::Failure {
                            code: ironrdp_pdu::nego::FailureCode::SSL_NOT_ALLOWED_BY_SERVER,
                        }))
                        .unwrap();
                        let _ = tcp.write_all(&cc).await;
                        let _ = tcp.flush().await;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    TargetMode::Normal => {
                        let _ = read_x224(&mut tcp).await;
                        let cc = encode_vec(&X224(ConnectionConfirm::Response {
                            flags: ResponseFlags::empty(),
                            protocol: SecurityProtocol::SSL,
                        }))
                        .unwrap();
                        if tcp.write_all(&cc).await.is_err() || tcp.flush().await.is_err() {
                            return;
                        }
                        let acceptor = TlsAcceptor::from(cfg.unwrap());
                        if let Ok(mut tls) = acceptor.accept(tcp).await {
                            let mut buf = [0u8; 1024];
                            let _ = tls.read(&mut buf).await; // read to EOF / whatever the peer sends
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Read one framed X.224 PDU (the CR) off `tcp`.
async fn read_x224(tcp: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let mut filled = 0;
    loop {
        if let Ok(Some(info)) = ironrdp_pdu::find_size(&buf[..filled]) {
            if filled >= info.length {
                buf.truncate(info.length);
                return Ok(buf);
            }
        }
        let n = tcp.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        filled += n;
    }
}

fn split_addr(addr: &str) -> (String, u16) {
    let (h, p) = addr.rsplit_once(':').unwrap();
    (h.to_string(), p.parse().unwrap())
}

fn generous_limits() -> ProbeLimits {
    ProbeLimits {
        dns_timeout_ms: 2_000,
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        total_timeout_ms: 10_000,
        max_banner_bytes: 8_192,
        max_frame_bytes: 65_536,
        max_chain_certificates: 8,
        max_certificate_bytes: 32_768,
        max_result_bytes: 262_144,
    }
}

fn rdp_assignment(host: &str, port: u16, server_name: &str, limits: ProbeLimits) -> ProbeAssignment {
    ProbeAssignment {
        job_id: "job-1".into(),
        asset_id: "asset-1".into(),
        endpoint_revision: 1,
        lease_token: vec![0u8; 32],
        protocol: ProbeProtocol::Rdp as i32,
        lease_expires_at_unix_ms: 1,
        limits: Some(limits),
        endpoint: Some(probe_assignment::Endpoint::Rdp(RdpProbeEndpoint {
            host: host.into(),
            port: u32::from(port),
            server_name: server_name.into(),
        })),
    }
}

// --- probe / match tests ----------------------------------------------------

#[tokio::test]
async fn probe_observes_leaf_and_matches_leaf_anchor() {
    install_provider();
    let (chain, key, leaf_fp) = self_signed("rdp.test");
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);

    let obs = probe::observe(&host, port, "rdp.test", &generous_limits())
        .await
        .expect("probe must reach the TLS handshake and capture the chain");
    assert_eq!(obs.leaf_fingerprint, leaf_fp);
    assert!(!obs.chain.is_empty());
    assert!(!obs.resolved_addresses.is_empty());

    let good = SessionAnchor {
        id: "a-good".into(),
        kind: "tls_leaf".into(),
        fingerprint: leaf_fp.clone(),
        required_dns_names: vec![],
        required_ip_addresses: vec![],
    };
    let m = probe::match_identity(&obs.chain, "", std::slice::from_ref(&good), UnixTime::now())
        .expect("correct leaf pin must match");
    assert_eq!(m.anchor_id, "a-good");
    assert_eq!(m.observed_fingerprint, leaf_fp);

    let bad = SessionAnchor {
        fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        ..good
    };
    assert!(probe::match_identity(&obs.chain, "", &[bad], UnixTime::now()).is_err());
}

#[tokio::test]
async fn probe_result_carries_tls_evidence() {
    install_provider();
    let (chain, key, leaf_fp) = self_signed("rdp.test");
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);

    let result = probe::run_to_result(rdp_assignment(&host, port, "rdp.test", generous_limits())).await;
    assert_eq!(result.outcome, ProbeOutcome::Succeeded as i32);
    assert!(!result.evidence.is_empty());
    let leaf = &result.evidence[0];
    assert_eq!(leaf.kind, ProbeEvidenceKind::TlsLeaf as i32);
    assert_eq!(leaf.sha256_fingerprint, leaf_fp);
    assert!(leaf.dns_names.iter().any(|d| d == "rdp.test"));
    assert!(leaf.valid_until_unix_ms > 0);
    match result.protocol_metadata {
        Some(probe_result::ProtocolMetadata::Tls(md)) => {
            assert!(!md.version.is_empty(), "a TLS version must be reported");
            assert_eq!(md.server_name, "rdp.test");
        }
        other => panic!("expected TLS protocol metadata, got {other:?}"),
    }
}

#[tokio::test]
async fn ca_anchor_matches_correct_name_only() {
    install_provider();
    let (chain, key, ca_pem, ca_fp) = ca_and_leaf("rdp.test", false);
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);
    let obs = probe::observe(&host, port, "rdp.test", &generous_limits())
        .await
        .expect("observe");

    let right = SessionAnchor {
        id: "ca-right".into(),
        kind: "tls_ca".into(),
        fingerprint: ca_fp.clone(),
        required_dns_names: vec!["rdp.test".into()],
        required_ip_addresses: vec![],
    };
    let m = probe::match_identity(&obs.chain, &ca_pem, std::slice::from_ref(&right), UnixTime::now())
        .expect("valid chain + correct name must match the CA anchor");
    assert_eq!(m.anchor_id, "ca-right");

    // Wrong required name: the leaf does not carry it → no match.
    let wrong_name = SessionAnchor {
        required_dns_names: vec!["evil.test".into()],
        ..right.clone()
    };
    assert!(probe::match_identity(&obs.chain, &ca_pem, &[wrong_name], UnixTime::now()).is_err());

    // A CA anchor with NO required name never authorizes a leaf.
    let no_name = SessionAnchor {
        required_dns_names: vec![],
        ..right.clone()
    };
    assert!(probe::match_identity(&obs.chain, &ca_pem, &[no_name], UnixTime::now()).is_err());

    // Wrong CA fingerprint (a different, unrelated CA) → no match even with the right name.
    let (_c2, _k2, _pem2, other_ca_fp) = ca_and_leaf("rdp.test", false);
    let wrong_ca = SessionAnchor {
        fingerprint: other_ca_fp,
        ..right
    };
    assert!(probe::match_identity(&obs.chain, &ca_pem, &[wrong_ca], UnixTime::now()).is_err());
}

#[tokio::test]
async fn ca_rotation_multiple_anchors_matches_active_ca() {
    install_provider();
    let (chain, key, ca_pem, ca_fp) = ca_and_leaf("rdp.test", false);
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);
    let obs = probe::observe(&host, port, "rdp.test", &generous_limits())
        .await
        .expect("observe");

    // An old (rotated-out) CA anchor plus the current one. Only the current CA is in
    // the chain, so the match must resolve to it.
    let (_c, _k, _pem, stale_ca_fp) = ca_and_leaf("rdp.test", false);
    let anchors = vec![
        SessionAnchor {
            id: "ca-old".into(),
            kind: "tls_ca".into(),
            fingerprint: stale_ca_fp,
            required_dns_names: vec!["rdp.test".into()],
            required_ip_addresses: vec![],
        },
        SessionAnchor {
            id: "ca-current".into(),
            kind: "tls_ca".into(),
            fingerprint: ca_fp,
            required_dns_names: vec!["rdp.test".into()],
            required_ip_addresses: vec![],
        },
    ];
    let m = probe::match_identity(&obs.chain, &ca_pem, &anchors, UnixTime::now()).expect("current CA must match");
    assert_eq!(m.anchor_id, "ca-current");
}

#[tokio::test]
async fn expired_leaf_fails_ca_match() {
    install_provider();
    let (chain, key, ca_pem, ca_fp) = ca_and_leaf("rdp.test", true);
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);
    // The observe handshake still completes (rustls does not reject an expired peer
    // cert on the client without verification); the identity match enforces validity.
    let obs = probe::observe(&host, port, "rdp.test", &generous_limits())
        .await
        .expect("observe");
    let anchor = SessionAnchor {
        id: "ca".into(),
        kind: "tls_ca".into(),
        fingerprint: ca_fp,
        required_dns_names: vec!["rdp.test".into()],
        required_ip_addresses: vec![],
    };
    assert!(
        probe::match_identity(&obs.chain, &ca_pem, &[anchor], UnixTime::now()).is_err(),
        "an expired leaf must not satisfy a CA anchor",
    );
}

#[tokio::test]
async fn negotiation_downgrade_is_rejected() {
    install_provider();
    let addr = spawn_target(TargetMode::Downgrade, None).await;
    let (host, port) = split_addr(&addr);
    match probe::observe(&host, port, "rdp.test", &generous_limits()).await {
        Err(ProbeFailure::InsecureDowngrade(_)) => {}
        other => panic!("expected InsecureDowngrade for a refused TLS negotiation, got {other:?}"),
    }
}

#[tokio::test]
async fn stalled_handshake_times_out() {
    install_provider();
    let addr = spawn_target(TargetMode::Silent, None).await;
    let (host, port) = split_addr(&addr);
    let mut limits = generous_limits();
    limits.handshake_timeout_ms = 300;
    match probe::observe(&host, port, "rdp.test", &limits).await {
        Err(ProbeFailure::ConnectionTimeout(_)) => {}
        other => panic!("expected ConnectionTimeout for a stalled handshake, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_chain_is_rejected() {
    install_provider();
    let (chain, key, _ca_pem, _ca_fp) = ca_and_leaf("rdp.test", false); // [leaf, ca] => 2 certs
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (host, port) = split_addr(&addr);
    let mut limits = generous_limits();
    limits.max_chain_certificates = 1;
    match probe::observe(&host, port, "rdp.test", &limits).await {
        Err(ProbeFailure::IdentityTooLarge(_)) => {}
        other => panic!("expected IdentityTooLarge for a chain over the ceiling, got {other:?}"),
    }
}

// --- verify-before-issue boundary (the security invariant) ------------------

/// Drive [`rdp_proxy::bridge::run`] over an in-memory mesh stream against a real TLS
/// target. `anchors` are the prepared trust anchors; the spy `issue` closure records
/// whether it was ever reached (it must NOT be, unless the identity matched).
/// Returns (outcome, issue_was_called).
async fn drive_bridge(
    target_addr: &str,
    target_server_ca: &str,
    anchors: Vec<SessionAnchor>,
) -> (rdp_proxy::bridge::BridgeOutcome, bool) {
    use rdp_proxy::record::RecorderConfig;

    let (mut client, server) = tokio::io::duplex(64 * 1024);

    // The browser's RDCleanPath request carrying an X.224 CR (TLS negotiation).
    let cr = encode_vec(&X224(ConnectionRequest {
        nego_data: None,
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::SSL,
    }))
    .unwrap();
    let req = RDCleanPathPdu::new_request(cr, "ignored".into(), String::new(), None)
        .unwrap()
        .to_der()
        .unwrap();
    client.write_all(&req).await.unwrap();
    client.flush().await.unwrap();

    let issued = Arc::new(AtomicBool::new(false));
    let issued_spy = issued.clone();
    let issue = move |_anchor_id: String, _fp: String| {
        let issued_spy = issued_spy.clone();
        async move {
            issued_spy.store(true, Ordering::SeqCst);
            Ok(zeroize::Zeroizing::new("s3cr3t".to_string()))
        }
    };

    let cancel = Arc::new(tokio::sync::Notify::new());

    // On the match path the bridge writes an RDCleanPath response then enters the
    // relay, reading from `client`; dropping `client` after a beat signals EOF so the
    // relay ends deterministically (the duplex buffer is large enough that the
    // bridge's small response never blocks in the meantime).
    let reader = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(client);
    });

    let report = rdp_proxy::bridge::run(
        target_addr,
        target_server_ca,
        "operator",
        &anchors,
        issue,
        cancel,
        server,
        None,
        RecorderConfig { part_size: 5 * 1024 * 1024, channel_bound: 16 },
    )
    .await;
    let _ = reader.await;
    (report.outcome, issued.load(Ordering::SeqCst))
}

#[tokio::test]
async fn bridge_never_issues_credential_on_identity_mismatch() {
    install_provider();
    let (chain, key, _leaf_fp) = self_signed("rdp.test");
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;

    // An anchor whose fingerprint does NOT match the target's leaf.
    let wrong = SessionAnchor {
        id: "wrong".into(),
        kind: "tls_leaf".into(),
        fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        required_dns_names: vec![],
        required_ip_addresses: vec![],
    };
    let (outcome, issued) = drive_bridge(&addr, "", vec![wrong]).await;
    assert_eq!(
        outcome,
        rdp_proxy::bridge::BridgeOutcome::IdentityUnverified,
        "a mismatched target identity must fail closed",
    );
    assert!(
        !issued,
        "IssueSessionCredential must NEVER be reached before a successful anchor match",
    );
}

#[tokio::test]
async fn bridge_never_issues_credential_with_no_anchors() {
    install_provider();
    let (chain, key, _leaf_fp) = self_signed("rdp.test");
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;
    let (outcome, issued) = drive_bridge(&addr, "", vec![]).await;
    assert_eq!(outcome, rdp_proxy::bridge::BridgeOutcome::IdentityUnverified);
    assert!(!issued, "no anchors must fail closed with no credential requested");
}

#[tokio::test]
async fn bridge_issues_credential_only_after_identity_match() {
    install_provider();
    let (chain, key, leaf_fp) = self_signed("rdp.test");
    let addr = spawn_target(TargetMode::Normal, Some(server_config(chain, key))).await;

    let good = SessionAnchor {
        id: "good".into(),
        kind: "tls_leaf".into(),
        fingerprint: leaf_fp,
        required_dns_names: vec![],
        required_ip_addresses: vec![],
    };
    let (_outcome, issued) = drive_bridge(&addr, "", vec![good]).await;
    assert!(
        issued,
        "a matched target identity must reach IssueSessionCredential",
    );
}
