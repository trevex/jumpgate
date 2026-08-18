//! Gateway→worker leg: mTLS-dial the chosen worker (pinning its SPIFFE identity),
//! CONNECT through forwarding the session token, then blind-pipe bytes.
//!
//! The worker's mesh leaf certificate carries only a SPIFFE URI SAN
//! (`spiffe://jumpgate/worker/<worker_id>`). We build a per-dial rustls
//! `ClientConfig` whose verifier PINS that exact identity (chain-to-mesh-CA AND
//! URI SAN == expected), so a mesh member impersonating another worker fails the
//! TLS handshake. After the handshake we forward an HTTP CONNECT carrying the
//! session token and, on `200`, hand the raw TLS stream to [`pump`].

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::connect::{self, ConnectError};
use crate::roster::WorkerEntry;
use crate::tls::MeshClientCerts;

/// A fixed placeholder DNS name for the rustls handshake. The mesh verifier
/// tolerates the missing DNS name and pins on the URI SAN instead, so the value
/// here is never name-checked — it only satisfies rustls' `ServerName` API.
const PLACEHOLDER_SNI: &str = "worker.mesh.jumpgate";

/// Errors from the gateway→worker proxy dial.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("tcp connect to worker failed: {0}")]
    Connect(std::io::Error),
    #[error("tls handshake / identity pin failed: {0}")]
    Tls(std::io::Error),
    #[error("building mesh client config failed: {0}")]
    Config(#[from] anyhow::Error),
    #[error("worker CONNECT failed: {0}")]
    Worker(#[from] ConnectError),
    #[error("invalid worker address: {0}")]
    Address(String),
}

/// mTLS-dial the chosen worker, pinning its SPIFFE identity
/// (`spiffe://jumpgate/worker/<worker_id>`), then CONNECT through forwarding the
/// session `token`. On a `200` response the established TLS stream is returned,
/// ready to be blind-piped with [`pump`].
pub async fn connect_worker(
    entry: &WorkerEntry,
    certs: &MeshClientCerts,
    token: &str,
    authority: &str,
) -> Result<TlsStream<TcpStream>, ProxyError> {
    // The verifier will reject any peer whose URI SAN != this exact identity.
    let expected = format!("spiffe://jumpgate/worker/{}", entry.worker_id);
    let client_config = certs.client_config(&expected)?;

    let tcp = TcpStream::connect(&entry.address)
        .await
        .map_err(ProxyError::Connect)?;

    // The verifier ignores this name (it pins on the URI SAN), but rustls still
    // requires a syntactically valid `ServerName`.
    let sni = rustls::pki_types::ServerName::try_from(PLACEHOLDER_SNI)
        .map_err(|_| ProxyError::Address("invalid placeholder SNI".into()))?;

    let connector = TlsConnector::from(client_config);
    // Identity mismatch surfaces HERE: the verifier runs during the handshake.
    let mut stream = connector.connect(sni, tcp).await.map_err(ProxyError::Tls)?;

    // Forward the CONNECT (carrying the session token) to the worker.
    stream
        .write_all(&connect::write_connect_request(authority, token))
        .await
        .map_err(ConnectError::Io)?;
    stream.flush().await.map_err(ConnectError::Io)?;

    // Expect `200 Connection Established`; any other status errors out.
    connect::read_worker_response(&mut stream).await?;

    Ok(stream)
}

/// Blind-pipe bytes between the external client stream and the worker stream
/// until either side closes. Returns `(client→worker, worker→client)` byte
/// counts. The caller holds the `lb::Guard`, which is dropped once this returns.
pub async fn pump<A, B>(mut client: A, mut worker: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut client, &mut worker).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ---- test PKI helpers -------------------------------------------------

    struct TestPki {
        ca_pem: String,
        gateway_cert_pem: String,
        gateway_key_pem: String,
        worker_cert_der: Vec<u8>,
        worker_key_der: Vec<u8>,
        ca_der: Vec<u8>,
    }

    /// Build a mesh CA and mint a gateway client leaf + a worker server leaf
    /// carrying the given worker SPIFFE URI SAN.
    fn build_pki(worker_spiffe: &str) -> TestPki {
        // CA
        let mut ca_params = rcgen::CertificateParams::new(vec!["mesh-ca".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Gateway client leaf.
        let mut gw_params = rcgen::CertificateParams::new(vec![]).unwrap();
        gw_params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://jumpgate/gateway/gw".try_into().unwrap(),
        )];
        let gw_key = rcgen::KeyPair::generate().unwrap();
        let gw_cert = gw_params.signed_by(&gw_key, &ca_cert, &ca_key).unwrap();

        // Worker server leaf with the requested SPIFFE URI SAN.
        let mut w_params = rcgen::CertificateParams::new(vec![]).unwrap();
        w_params.subject_alt_names = vec![rcgen::SanType::URI(worker_spiffe.try_into().unwrap())];
        let w_key = rcgen::KeyPair::generate().unwrap();
        let w_cert = w_params.signed_by(&w_key, &ca_cert, &ca_key).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            gateway_cert_pem: gw_cert.pem(),
            gateway_key_pem: gw_key.serialize_pem(),
            worker_cert_der: w_cert.der().to_vec(),
            worker_key_der: w_key.serialize_der(),
            ca_der: ca_cert.der().to_vec(),
        }
    }

    fn gateway_certs(pki: &TestPki) -> MeshClientCerts {
        MeshClientCerts {
            cert_pem: pki.gateway_cert_pem.clone().into_bytes(),
            key_pem: pki.gateway_key_pem.clone().into_bytes(),
            ca_pem: pki.ca_pem.clone().into_bytes(),
        }
    }

    /// Build the stub worker's mTLS server config: present the worker leaf and
    /// require + verify a client cert chaining to the mesh CA.
    fn stub_server_config(pki: &TestPki) -> Arc<rustls::ServerConfig> {
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

    /// Start a stub worker: accept one mTLS conn, read a CONNECT request, reply
    /// `200`, then echo bytes. Returns the bound address.
    async fn spawn_stub_worker(pki: &TestPki) -> std::net::SocketAddr {
        let server_config = stub_server_config(pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => return, // handshake rejected (e.g. identity-pin mismatch)
            };

            // Read the CONNECT request header.
            let _req = crate::connect::read_connect(&mut tls).await.unwrap();
            tls.write_all(crate::connect::response_established())
                .await
                .unwrap();
            tls.flush().await.unwrap();

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

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn entry(worker_id: &str, addr: std::net::SocketAddr) -> WorkerEntry {
        WorkerEntry {
            worker_id: worker_id.to_string(),
            protocol: "ssh".to_string(),
            address: addr.to_string(),
            capacity: 0,
        }
    }

    // ---- tests ------------------------------------------------------------

    #[tokio::test]
    async fn connect_worker_happy() {
        install_provider();
        let pki = build_pki("spiffe://jumpgate/worker/w1");
        let addr = spawn_stub_worker(&pki).await;
        let certs = gateway_certs(&pki);

        let entry = entry("w1", addr);
        let stream = connect_worker(&entry, &certs, "session-token-abc", "asset-1")
            .await
            .expect("connect_worker should succeed for matching identity");

        // Round-trip bytes through the echo worker via a raw split (pump would
        // need a second peer; here we exercise the established tunnel directly).
        let (mut rd, mut wr) = tokio::io::split(stream);
        wr.write_all(b"hello worker").await.unwrap();
        wr.flush().await.unwrap();
        let mut got = vec![0u8; b"hello worker".len()];
        rd.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello worker");
    }

    #[tokio::test]
    async fn pump_round_trips_bytes() {
        install_provider();
        let pki = build_pki("spiffe://jumpgate/worker/w1");
        let addr = spawn_stub_worker(&pki).await;
        let certs = gateway_certs(&pki);

        let worker = connect_worker(&entry("w1", addr), &certs, "tok", "asset-1")
            .await
            .expect("connect_worker ok");

        // A client-side in-memory duplex; pump copies both directions.
        let (mut client_end, gateway_end) = tokio::io::duplex(4096);
        let pump_task = tokio::spawn(async move { pump(gateway_end, worker).await });

        client_end.write_all(b"ping through pump").await.unwrap();
        client_end.flush().await.unwrap();
        let mut got = vec![0u8; b"ping through pump".len()];
        client_end.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping through pump");

        // Close the client side; pump should finish.
        drop(client_end);
        let _ = pump_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_worker_san_mismatch() {
        install_provider();
        // Stub worker presents worker/w2 ...
        let pki = build_pki("spiffe://jumpgate/worker/w2");
        let addr = spawn_stub_worker(&pki).await;
        let certs = gateway_certs(&pki);

        // ... but we expect worker/w1: the TLS handshake must fail on the pin.
        let entry = entry("w1", addr);
        let err = connect_worker(&entry, &certs, "tok", "asset-1")
            .await
            .expect_err("identity mismatch must fail the handshake");

        // Must be a TLS (handshake) failure, not a later CONNECT/Worker error.
        match err {
            ProxyError::Tls(_) => {}
            other => panic!("expected ProxyError::Tls (handshake), got {other:?}"),
        }
    }
}
