//! End-to-end integration test for the gateway's per-connection path, driven
//! entirely in-process through the public `gateway::` API — no Go warden.
//!
//! Each case wires the whole leg: a TLS client sends a `CONNECT <asset>` request
//! with an `Authorization: Bearer <token>` header over the external
//! (client↔gateway) TLS leg;
//! [`gateway::handle_connection`] verifies the token, picks a worker from the
//! injected roster, mTLS-dials a stub worker (pinning its SPIFFE URI SAN),
//! forwards the CONNECT, replies `200`, and blind-pipes bytes.
//!
//! Legs:
//!
//! - client ↔ gateway: server-TLS only (self-signed leaf w/ DNS SAN, client
//!   trusts its CA; the client presents NO cert). ALPN `http/1.1`.
//! - gateway ↔ worker: mesh mTLS, URI-SAN-only leaves, SPIFFE identity pin.
//!
//! Cases: happy path (real byte echo), 403 (bad token), 502 (no worker), 502
//! (SAN mismatch: stub presents `worker/w2` but the roster says `w1`).

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use gateway::tls::MeshClientCerts;
use gateway::{handle_connection, GatewayState};

// ---------------------------------------------------------------------------
// Mesh PKI (gateway↔worker leg): a CA, a gateway client leaf, a worker server
// leaf. Leaves carry only URI SANs (SPIFFE), mirroring the real mesh.
// ---------------------------------------------------------------------------

/// The mesh trust material plus the raw DER needed to stand up a stub worker
/// server config.
struct MeshPki {
    ca_pem: String,
    gateway_cert_pem: String,
    gateway_key_pem: String,
    worker_cert_der: Vec<u8>,
    worker_key_der: Vec<u8>,
    ca_der: Vec<u8>,
}

/// Build a mesh CA, a gateway client leaf (`spiffe://jumpgate/gateway/gw`), and
/// a worker server leaf carrying `worker_spiffe` as its sole URI SAN.
fn build_mesh_pki(worker_spiffe: &str) -> MeshPki {
    // CA.
    let mut ca_params = rcgen::CertificateParams::new(vec!["mesh-ca".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Gateway client leaf (URI SAN only).
    let mut gw_params = rcgen::CertificateParams::new(vec![]).unwrap();
    gw_params.subject_alt_names = vec![rcgen::SanType::URI(
        "spiffe://jumpgate/gateway/gw".try_into().unwrap(),
    )];
    let gw_key = rcgen::KeyPair::generate().unwrap();
    let gw_cert = gw_params.signed_by(&gw_key, &ca_cert, &ca_key).unwrap();

    // Worker server leaf with the requested SPIFFE URI SAN (URI SAN only).
    let mut w_params = rcgen::CertificateParams::new(vec![]).unwrap();
    w_params.subject_alt_names = vec![rcgen::SanType::URI(worker_spiffe.try_into().unwrap())];
    let w_key = rcgen::KeyPair::generate().unwrap();
    let w_cert = w_params.signed_by(&w_key, &ca_cert, &ca_key).unwrap();

    MeshPki {
        ca_pem: ca_cert.pem(),
        gateway_cert_pem: gw_cert.pem(),
        gateway_key_pem: gw_key.serialize_pem(),
        worker_cert_der: w_cert.der().to_vec(),
        worker_key_der: w_key.serialize_der(),
        ca_der: ca_cert.der().to_vec(),
    }
}

/// The gateway's mesh client certs (the identity `handle_connection` presents to
/// the worker), built from the PKI.
fn gateway_mesh_certs(pki: &MeshPki) -> MeshClientCerts {
    MeshClientCerts {
        cert_pem: pki.gateway_cert_pem.clone().into_bytes(),
        key_pem: pki.gateway_key_pem.clone().into_bytes(),
        ca_pem: pki.ca_pem.clone().into_bytes(),
    }
}

// ---------------------------------------------------------------------------
// Stub worker (gateway↔worker leg peer): mTLS server that requires + verifies a
// client cert against the mesh CA, reads a CONNECT, replies 200, then echoes.
// ---------------------------------------------------------------------------

/// Build the stub worker's mTLS server config: present the worker leaf and
/// require + verify the client's cert chains to the mesh CA.
fn stub_worker_server_config(pki: &MeshPki) -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(pki.ca_der.clone())).unwrap();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let cert = CertificateDer::from(pki.worker_cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.worker_key_der.clone()));

    Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert], key)
            .unwrap(),
    )
}

/// Spawn a stub worker: accept one mTLS conn, read a CONNECT, reply `200`, then
/// echo bytes until close. Returns the bound `127.0.0.1:0` address.
async fn spawn_stub_worker(pki: &MeshPki) -> SocketAddr {
    let server_config = stub_worker_server_config(pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(_) => return, // handshake rejected (e.g. client-cert / identity pin)
        };

        // Read the CONNECT header the gateway forwards.
        if gateway::connect::read_connect(&mut tls).await.is_err() {
            return;
        }
        if tls
            .write_all(gateway::connect::response_established())
            .await
            .is_err()
        {
            return;
        }
        let _ = tls.flush().await;

        // Echo everything else back.
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = tls.flush().await;
                }
            }
        }
    });

    addr
}

// ---------------------------------------------------------------------------
// External (client↔gateway) TLS leg: a self-signed server cert with a DNS SAN
// `localhost`; the client trusts that cert. Server-TLS only (no client cert).
// ---------------------------------------------------------------------------

/// The external server acceptor plus the DER cert the client must trust.
struct ExternalTls {
    acceptor: TlsAcceptor,
    server_cert_der: Vec<u8>,
}

/// Build the external server TLS. A single self-signed leaf (`localhost`) acts
/// as both the server cert and the client's trust anchor. ALPN `http/1.1` to
/// match `gateway::tls::server_config`.
fn build_external_tls() -> ExternalTls {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let leaf = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = leaf.cert.der().to_vec();
    let key_der = leaf.key_pair.serialize_der();

    let cert = CertificateDer::from(cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    ExternalTls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        server_cert_der: cert_der,
    }
}

/// Build the client-side TLS connector that trusts the external server's leaf.
fn client_connector(server_cert_der: &[u8]) -> TlsConnector {
    use rustls::pki_types::CertificateDer;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_cert_der.to_vec()))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Token minting (reuses the pasetors v4.public shape from `token.rs` tests).
// ---------------------------------------------------------------------------

/// Mint a valid v4.public session token with warden's claim layout, signed with
/// a fresh Ed25519 keypair. Returns `(token, 32-byte-ed25519-public-key)`.
fn mint_token(proto: &str) -> (String, Vec<u8>) {
    use pasetors::claims::Claims as PasetoClaims;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::public;
    use pasetors::version4::V4;
    use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let pk_bytes = kp.public.as_bytes().to_vec();

    let now = OffsetDateTime::now_utc();
    let exp = now + Duration::days(3650); // far future
    let past = now - Duration::seconds(120);

    let mut claims = PasetoClaims::new_expires_in(&core::time::Duration::from_secs(60)).unwrap();
    claims.expiration(&exp.format(&Rfc3339).unwrap()).unwrap();
    claims.not_before(&past.format(&Rfc3339).unwrap()).unwrap();
    claims.issued_at(&past.format(&Rfc3339).unwrap()).unwrap();

    claims
        .token_identifier("11111111-1111-1111-1111-111111111111")
        .unwrap();
    claims
        .subject("22222222-2222-2222-2222-222222222222")
        .unwrap();
    claims
        .add_additional("asset", "33333333-3333-3333-3333-333333333333")
        .unwrap();
    claims.add_additional("proto", proto).unwrap();
    claims
        .add_additional("cnf", "SHA256:testfingerprint")
        .unwrap();

    let token = public::sign(&kp.secret, &claims, None, None).unwrap();
    (token, pk_bytes)
}

// ---------------------------------------------------------------------------
// Test harness: front door + client helpers.
// ---------------------------------------------------------------------------

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Bind a "gateway front door" TCP listener, then in a task accept ONE conn,
/// TLS-accept it with the external server config, and hand the resulting stream
/// to `gateway::handle_connection`. Returns the bound address.
async fn spawn_gateway_front_door(state: GatewayState, external: ExternalTls) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = external.acceptor;

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(_) => return,
        };
        handle_connection(state, tls).await;
    });

    addr
}

/// Connect + TLS-handshake to the gateway front door, trusting `server_cert_der`.
async fn client_tls_connect(
    addr: SocketAddr,
    server_cert_der: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let connector = client_connector(server_cert_der);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(sni, tcp).await.unwrap()
}

/// Read an HTTP status line (`HTTP/1.1 <code> ...`) up to the first CRLF and
/// return the numeric status code.
async fn read_status_code<R: AsyncReadExt + Unpin>(stream: &mut R) -> u16 {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(n != 0, "EOF before status line; got: {line:?}");
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
        assert!(line.len() <= 512, "status line too long");
    }
    let text = String::from_utf8(line).unwrap();
    // "HTTP/1.1 200 Connection Established\r\n" -> parse the middle token.
    let code = text
        .split_whitespace()
        .nth(1)
        .expect("status line has a code");
    code.parse().expect("status code is numeric")
}

/// Drain the rest of the CONNECT response headers (through the terminating
/// blank line) so subsequent reads see only tunneled body bytes.
async fn drain_response_headers<R: AsyncReadExt + Unpin>(stream: &mut R) {
    // We already consumed the status line's CRLF in `read_status_code`. The
    // gateway's success response is exactly `...Established\r\n\r\n`, so one more
    // CRLF terminates the headers.
    let mut byte = [0u8; 1];
    let mut recent = Vec::new();
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert!(n != 0, "EOF while draining headers");
        recent.push(byte[0]);
        if recent.ends_with(b"\r\n") {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Happy path: CONNECT → verify → pick → mTLS dial (SPIFFE pin) → 200 → real
/// byte echo through the gateway to the stub worker.
#[tokio::test]
async fn e2e_happy_path() {
    install_provider();

    let pki = build_mesh_pki("spiffe://jumpgate/worker/w1");
    let worker_addr = spawn_stub_worker(&pki).await;
    let (token, pubkey) = mint_token("ssh");

    let roster = gateway::roster::Roster::default();
    roster.apply_added("w1", "ssh", &worker_addr.to_string(), 10);
    let state = GatewayState {
        roster,
        counters: gateway::lb::LoadCounters::default(),
        mesh_certs: gateway_mesh_certs(&pki),
        verification_key: Arc::new(RwLock::new(Some(pubkey))),
    };

    let external = build_external_tls();
    let server_cert_der = external.server_cert_der.clone();
    let front = spawn_gateway_front_door(state, external).await;

    let mut client = client_tls_connect(front, &server_cert_der).await;
    let req = format!("CONNECT asset-1 HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let code = read_status_code(&mut client).await;
    assert_eq!(code, 200, "expected 200 Connection Established");
    drain_response_headers(&mut client).await;

    // Prove real byte echo through the gateway pump to the stub worker.
    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0u8; 5];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(
        &got, b"hello",
        "echoed bytes must round-trip through the pump"
    );
}

/// Bad token: signed by a DIFFERENT key than the one in `verification_key` →
/// the gateway rejects with `403` and never dials a worker.
#[tokio::test]
async fn e2e_bad_token_403() {
    install_provider();

    let pki = build_mesh_pki("spiffe://jumpgate/worker/w1");
    let worker_addr = spawn_stub_worker(&pki).await;

    // Mint a token, but inject a DIFFERENT key into the gateway.
    let (token, _real_pk) = mint_token("ssh");
    let (_other_token, wrong_pk) = mint_token("ssh");

    let roster = gateway::roster::Roster::default();
    roster.apply_added("w1", "ssh", &worker_addr.to_string(), 10);
    let state = GatewayState {
        roster,
        counters: gateway::lb::LoadCounters::default(),
        mesh_certs: gateway_mesh_certs(&pki),
        verification_key: Arc::new(RwLock::new(Some(wrong_pk))),
    };

    let external = build_external_tls();
    let server_cert_der = external.server_cert_der.clone();
    let front = spawn_gateway_front_door(state, external).await;

    let mut client = client_tls_connect(front, &server_cert_der).await;
    let req = format!("CONNECT asset-1 HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let code = read_status_code(&mut client).await;
    assert_eq!(code, 403, "wrong-key token must be rejected with 403");
}

/// No worker: empty roster → the gateway has nothing to pick and replies `502`.
#[tokio::test]
async fn e2e_no_worker_502() {
    install_provider();

    let pki = build_mesh_pki("spiffe://jumpgate/worker/w1");
    let (token, pubkey) = mint_token("ssh");

    // Empty roster: no apply_added.
    let state = GatewayState {
        roster: gateway::roster::Roster::default(),
        counters: gateway::lb::LoadCounters::default(),
        mesh_certs: gateway_mesh_certs(&pki),
        verification_key: Arc::new(RwLock::new(Some(pubkey))),
    };

    let external = build_external_tls();
    let server_cert_der = external.server_cert_der.clone();
    let front = spawn_gateway_front_door(state, external).await;

    let mut client = client_tls_connect(front, &server_cert_der).await;
    let req = format!("CONNECT asset-1 HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let code = read_status_code(&mut client).await;
    assert_eq!(code, 502, "no available worker must yield 502");
}

/// SAN mismatch: the stub worker presents `spiffe://jumpgate/worker/w2`, but the
/// roster entry is `w1`, so the gateway pins `worker/w1`. The worker dial's
/// identity pin fails the mTLS handshake → the gateway replies `502`.
#[tokio::test]
async fn e2e_san_mismatch_502() {
    install_provider();

    // Stub presents worker/w2 ...
    let pki = build_mesh_pki("spiffe://jumpgate/worker/w2");
    let worker_addr = spawn_stub_worker(&pki).await;
    let (token, pubkey) = mint_token("ssh");

    // ... but the roster (hence the pin) says w1.
    let roster = gateway::roster::Roster::default();
    roster.apply_added("w1", "ssh", &worker_addr.to_string(), 10);
    let state = GatewayState {
        roster,
        counters: gateway::lb::LoadCounters::default(),
        mesh_certs: gateway_mesh_certs(&pki),
        verification_key: Arc::new(RwLock::new(Some(pubkey))),
    };

    let external = build_external_tls();
    let server_cert_der = external.server_cert_der.clone();
    let front = spawn_gateway_front_door(state, external).await;

    let mut client = client_tls_connect(front, &server_cert_der).await;
    let req = format!("CONNECT asset-1 HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let code = read_status_code(&mut client).await;
    assert_eq!(code, 502, "SPIFFE identity-pin mismatch must yield 502");
}
