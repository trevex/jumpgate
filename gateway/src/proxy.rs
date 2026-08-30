//! Gateway→worker leg: mTLS-dial the chosen worker (pinning its SPIFFE identity),
//! CONNECT through forwarding the session token, then blind-pipe bytes.
//!
//! The worker's mesh leaf certificate carries only a SPIFFE URI SAN
//! (`spiffe://jumpgate/worker/<worker_id>`). We build a per-dial rustls
//! `ClientConfig` whose verifier PINS that exact identity (chain-to-mesh-CA AND
//! URI SAN == expected), so a mesh member impersonating another worker fails the
//! TLS handshake. After the handshake we forward an HTTP CONNECT carrying the
//! session token and, on `200`, hand the raw TLS stream to [`pump_bounded`].

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
/// ready to be blind-piped with [`pump_bounded`].
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

/// mTLS-dial the chosen worker exactly like [`connect_worker`], but forward the
/// **terminal** CONNECT preamble (`X-Jumpgate-Terminal: 1` +
/// `X-Jumpgate-Login: <login>`) so the worker branches to its framed-terminal
/// ingress instead of the russh SSH server. On `200` the established mesh TLS
/// stream is returned, ready for the gateway's frame relay.
pub async fn connect_worker_terminal(
    entry: &WorkerEntry,
    certs: &MeshClientCerts,
    token: &str,
    authority: &str,
    login: &str,
) -> Result<TlsStream<TcpStream>, ProxyError> {
    let expected = format!("spiffe://jumpgate/worker/{}", entry.worker_id);
    let client_config = certs.client_config(&expected)?;

    let tcp = TcpStream::connect(&entry.address)
        .await
        .map_err(ProxyError::Connect)?;

    let sni = rustls::pki_types::ServerName::try_from(PLACEHOLDER_SNI)
        .map_err(|_| ProxyError::Address("invalid placeholder SNI".into()))?;

    let connector = TlsConnector::from(client_config);
    let mut stream = connector.connect(sni, tcp).await.map_err(ProxyError::Tls)?;

    stream
        .write_all(&connect::write_terminal_connect_request(
            authority, token, login,
        ))
        .await
        .map_err(ConnectError::Io)?;
    stream.flush().await.map_err(ConnectError::Io)?;

    connect::read_worker_response(&mut stream).await?;

    Ok(stream)
}

/// Dial a k8s broker's gateway-facing front door over mesh mTLS, pinning
/// `spiffe://jumpgate/broker/<broker_id>` and negotiating `http/1.1`. Unlike
/// [`connect_worker`], there is NO CONNECT preamble: the caller replays kubectl's
/// buffered request head into the returned stream and then pumps bytes — the
/// broker treats the connection as a raw HTTP/1.1 server conn.
pub async fn connect_broker(
    entry: &WorkerEntry,
    certs: &MeshClientCerts,
    broker_id: &str,
) -> Result<TlsStream<TcpStream>, ProxyError> {
    // The verifier will reject any peer whose URI SAN != this exact identity.
    let expected = format!("spiffe://jumpgate/broker/{broker_id}");
    let client_config = certs.client_config_h1(&expected)?;

    let tcp = TcpStream::connect(&entry.address)
        .await
        .map_err(ProxyError::Connect)?;

    // The verifier ignores this name (it pins on the URI SAN), but rustls still
    // requires a syntactically valid `ServerName`.
    let sni = rustls::pki_types::ServerName::try_from(PLACEHOLDER_SNI)
        .map_err(|_| ProxyError::Address("invalid placeholder SNI".into()))?;

    let connector = TlsConnector::from(client_config);
    // Identity mismatch surfaces HERE: the verifier runs during the handshake.
    let stream = connector.connect(sni, tcp).await.map_err(ProxyError::Tls)?;

    Ok(stream)
}

/// Resource bounds applied to a proxied byte pump (and the WS terminal relay):
/// an idle timeout (no bytes either direction) and an absolute lifetime cap.
/// A zero [`Duration`] disables the corresponding bound.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// Tear the session down if no bytes flow in EITHER direction for this long.
    /// Zero disables the idle check.
    pub idle_timeout: Duration,
    /// Absolute wall-clock cap on the session. Zero = unlimited.
    pub max_lifetime: Duration,
}

impl SessionLimits {
    /// No bounds — behaves like a bare `copy_bidirectional`. Handy for tests and
    /// callers that opt out.
    pub const UNBOUNDED: SessionLimits = SessionLimits {
        idle_timeout: Duration::ZERO,
        max_lifetime: Duration::ZERO,
    };
}

/// Why a bounded pump/relay stopped. `Closed` is the normal path (one side hung
/// up); the timeout variants signal a bound tripped so the caller can log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A peer closed the connection (or a copy errored) — the ordinary exit.
    Closed,
    /// No bytes flowed in either direction within `idle_timeout`.
    Idle,
    /// The absolute `max_lifetime` cap elapsed.
    Lifetime,
}

/// Blind-pipe bytes between the two streams, bounded by
/// `limits`: an idle timeout (no bytes EITHER direction) and an absolute
/// lifetime cap. Returns the byte counts and why the pump stopped.
///
/// A [`StopReason::Idle`]/[`StopReason::Lifetime`] is a normal exit — the caller
/// runs the SAME teardown (drop the load guard, etc.) as on `Closed`. Any real
/// I/O error still surfaces as `Err`.
///
/// Correctness: the idle clock is reset on every non-zero read in either
/// direction, so an actively flowing session is never torn down; only a session
/// with no progress for `idle_timeout` (or one exceeding `max_lifetime`) is.
pub async fn pump_bounded<A, B>(
    client: A,
    worker: B,
    limits: SessionLimits,
) -> std::io::Result<((u64, u64), StopReason)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Fast path: no bounds → plain bidirectional copy.
    if limits.idle_timeout.is_zero() && limits.max_lifetime.is_zero() {
        let mut client = client;
        let mut worker = worker;
        let counts = tokio::io::copy_bidirectional(&mut client, &mut worker).await?;
        return Ok((counts, StopReason::Closed));
    }

    let inner = copy_bidirectional_idle(client, worker, limits.idle_timeout);

    if limits.max_lifetime.is_zero() {
        return inner.await;
    }
    match tokio::time::timeout(limits.max_lifetime, inner).await {
        Ok(res) => res,
        // Absolute cap tripped: report it; the caller tears the session down.
        Err(_elapsed) => Ok(((0, 0), StopReason::Lifetime)),
    }
}

/// Idle-aware bidirectional copy: pump bytes both ways, resetting a shared idle
/// clock on any non-zero read. If `idle_timeout` is non-zero and no bytes flow
/// in either direction within it, stop with [`StopReason::Idle`].
///
/// Implemented as a `select!` loop over both read directions, each `read`
/// wrapped in `tokio::time::timeout(idle_timeout, …)`; a per-direction timeout
/// only counts as idle when the OTHER direction has also been idle since the
/// last activity, so a one-way-busy stream (e.g. a long download) is preserved.
async fn copy_bidirectional_idle<A, B>(
    mut client: A,
    mut worker: B,
    idle_timeout: Duration,
) -> std::io::Result<((u64, u64), StopReason)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut c2w: u64 = 0; // client → worker bytes
    let mut w2c: u64 = 0; // worker → client bytes
    let mut cbuf = vec![0u8; 16 * 1024];
    let mut wbuf = vec![0u8; 16 * 1024];
    let mut client_eof = false;
    let mut worker_eof = false;

    // A read future is "idle-limited" only when the timeout is enabled. We track
    // the last-activity instant and, on a per-read timeout, only declare the
    // whole session idle if BOTH directions have been quiet since then.
    let mut last_activity = tokio::time::Instant::now();

    loop {
        if client_eof && worker_eof {
            return Ok(((c2w, w2c), StopReason::Closed));
        }

        // Deadline for the earliest allowable idle trip.
        let deadline = last_activity + idle_timeout;

        tokio::select! {
            // client → worker
            r = read_with_deadline(&mut client, &mut cbuf, idle_timeout, deadline), if !client_eof => {
                match r {
                    ReadOutcome::Data(n) => {
                        last_activity = tokio::time::Instant::now();
                        worker.write_all(&cbuf[..n]).await?;
                        worker.flush().await?;
                        c2w += n as u64;
                    }
                    ReadOutcome::Eof => {
                        client_eof = true;
                        // Half-close the worker's write side so the peer sees EOF.
                        let _ = worker.shutdown().await;
                    }
                    ReadOutcome::Idle => return Ok(((c2w, w2c), StopReason::Idle)),
                    ReadOutcome::Err(e) => return Err(e),
                }
            }

            // worker → client
            r = read_with_deadline(&mut worker, &mut wbuf, idle_timeout, deadline), if !worker_eof => {
                match r {
                    ReadOutcome::Data(n) => {
                        last_activity = tokio::time::Instant::now();
                        client.write_all(&wbuf[..n]).await?;
                        client.flush().await?;
                        w2c += n as u64;
                    }
                    ReadOutcome::Eof => {
                        worker_eof = true;
                        let _ = client.shutdown().await;
                    }
                    ReadOutcome::Idle => return Ok(((c2w, w2c), StopReason::Idle)),
                    ReadOutcome::Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Outcome of a single deadline-bounded read.
enum ReadOutcome {
    Data(usize),
    Eof,
    Idle,
    Err(std::io::Error),
}

/// Read into `buf`, bounded by the shared idle `deadline`. `idle_timeout` being
/// zero disables the bound (waits indefinitely). A read that completes with a
/// non-zero count is `Data`; a clean `0` is `Eof`; the deadline elapsing with no
/// data is `Idle`.
async fn read_with_deadline<R>(
    r: &mut R,
    buf: &mut [u8],
    idle_timeout: Duration,
    deadline: tokio::time::Instant,
) -> ReadOutcome
where
    R: AsyncRead + Unpin,
{
    if idle_timeout.is_zero() {
        return match r.read(buf).await {
            Ok(0) => ReadOutcome::Eof,
            Ok(n) => ReadOutcome::Data(n),
            Err(e) => ReadOutcome::Err(e),
        };
    }
    match tokio::time::timeout_at(deadline, r.read(buf)).await {
        Ok(Ok(0)) => ReadOutcome::Eof,
        Ok(Ok(n)) => ReadOutcome::Data(n),
        Ok(Err(e)) => ReadOutcome::Err(e),
        Err(_elapsed) => ReadOutcome::Idle,
    }
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

        let mut worker = connect_worker(&entry("w1", addr), &certs, "tok", "asset-1")
            .await
            .expect("connect_worker ok");

        // A client-side in-memory duplex; copy_bidirectional copies both directions.
        let (mut client_end, mut gateway_end) = tokio::io::duplex(4096);
        let pump_task = tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut gateway_end, &mut worker).await
        });

        client_end.write_all(b"ping through pump").await.unwrap();
        client_end.flush().await.unwrap();
        let mut got = vec![0u8; b"ping through pump".len()];
        client_end.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping through pump");

        // Close the client side; pump should finish.
        drop(client_end);
        let _ = pump_task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pump_bounded_idle_timeout_fires() {
        // Two duplex pairs standing in for client and worker; neither side ever
        // sends, so the idle timeout must trip and stop the pump.
        let (_client_peer, client) = tokio::io::duplex(64);
        let (_worker_peer, worker) = tokio::io::duplex(64);
        let limits = SessionLimits {
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::ZERO,
        };
        let ((c2w, w2c), reason) = pump_bounded(client, worker, limits).await.unwrap();
        assert_eq!(reason, StopReason::Idle);
        assert_eq!((c2w, w2c), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn pump_bounded_max_lifetime_fires() {
        // An always-idle session; the absolute cap trips even with idle disabled.
        let (_client_peer, client) = tokio::io::duplex(64);
        let (_worker_peer, worker) = tokio::io::duplex(64);
        let limits = SessionLimits {
            idle_timeout: Duration::ZERO,
            max_lifetime: Duration::from_secs(10),
        };
        let (_counts, reason) = pump_bounded(client, worker, limits).await.unwrap();
        assert_eq!(reason, StopReason::Lifetime);
    }

    #[tokio::test(start_paused = true)]
    async fn pump_bounded_active_session_not_torn_down() {
        // Data flows steadily just under the idle window; the pump must keep going
        // and only stop when the peer actually closes — NOT on a false idle trip.
        let (mut client_peer, client) = tokio::io::duplex(1024);
        let (mut worker_peer, worker) = tokio::io::duplex(1024);
        let limits = SessionLimits {
            idle_timeout: Duration::from_secs(5),
            max_lifetime: Duration::ZERO,
        };
        let pump = tokio::spawn(async move { pump_bounded(client, worker, limits).await });

        // Send a byte every 2s (well under the 5s idle window) a few times.
        for _ in 0..5 {
            client_peer.write_all(b"x").await.unwrap();
            client_peer.flush().await.unwrap();
            // Drain what the pump forwards so the worker side doesn't backpressure.
            let mut b = [0u8; 1];
            worker_peer.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"x");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Now go quiet: the idle window elapses → Idle stop, proving the earlier
        // activity kept it alive (it did not trip during the active phase).
        let ((c2w, _w2c), reason) = pump.await.unwrap().unwrap();
        assert_eq!(reason, StopReason::Idle);
        assert_eq!(c2w, 5);
    }

    /// Start a stub broker: accept one mTLS conn and just hold it open (no
    /// CONNECT preamble — `connect_broker` sends none). Returns the bound address.
    async fn spawn_stub_broker(pki: &TestPki) -> std::net::SocketAddr {
        let server_config = stub_server_config(pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => return, // handshake rejected (identity-pin mismatch)
            };
            // Echo whatever the gateway replays (the buffered request head).
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

    #[tokio::test]
    async fn connect_broker_happy() {
        install_provider();
        // Stub broker presents broker/broker-0 and we pin broker-0: handshake ok.
        let pki = build_pki("spiffe://jumpgate/broker/broker-0");
        let addr = spawn_stub_broker(&pki).await;
        let certs = gateway_certs(&pki);

        let mut stream = connect_broker(&entry("broker-0", addr), &certs, "broker-0")
            .await
            .expect("connect_broker should succeed for matching identity");

        // No CONNECT preamble: bytes we write are the replayed head; echoed back.
        stream
            .write_all(b"GET /api/v1/pods HTTP/1.1")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut got = vec![0u8; b"GET /api/v1/pods HTTP/1.1".len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"GET /api/v1/pods HTTP/1.1");
    }

    #[tokio::test]
    async fn connect_broker_san_mismatch() {
        install_provider();
        // Stub presents a WORKER identity (or any non-broker-0 SPIFFE) ...
        let pki = build_pki("spiffe://jumpgate/broker/other");
        let addr = spawn_stub_broker(&pki).await;
        let certs = gateway_certs(&pki);

        // ... but we pin broker-0: the TLS handshake must fail on the pin.
        let err = connect_broker(&entry("broker-0", addr), &certs, "broker-0")
            .await
            .expect_err("identity mismatch must fail the handshake");

        match err {
            ProxyError::Tls(_) => {}
            other => panic!("expected ProxyError::Tls (handshake), got {other:?}"),
        }
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
