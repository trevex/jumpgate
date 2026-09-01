//! The data-plane front door: an mTLS server that accepts the gateway's
//! connection (pinned to the gateway's mesh SPIFFE id), reads the HTTP/1.1
//! CONNECT preamble, and — on `X-Jumpgate-Rdp: 1` — redeems the session with
//! warden and runs the IronRDP [`crate::bridge`].
//!
//! Mirrors ssh-proxy's `server.rs` accept loop + health listener, but the only
//! ingress is the framed RDP opcode stream (no russh SSH server): the browser
//! never speaks a native protocol here, the gateway relays opcode frames.

use std::fs;
use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use jumpgate_mesh::tls::MeshClientCerts;

use crate::config::Config;
use crate::control::SessionRegistry;
use crate::record::{PartUploader, RecordStatus, RecorderConfig, S3Uploader};
use crate::setup::{setup_session, TargetCredential};

/// Current wall-clock time as unix milliseconds (saturating at 0 before the
/// epoch). Stamps the recording end timestamp.
fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A finished session to report to warden via the control plane: the id, the end
/// reason, and — for a recorded session — its recording disposition.
pub struct SessionEndReport {
    pub session_id: String,
    pub reason: String,
    pub recording: Option<RecordingOutcome>,
}

/// The recorded-session disposition carried to warden (a port of ssh-proxy's).
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

/// A synthetic `failed` recording outcome for a `recording_required` session whose
/// multipart upload could never be opened (nothing was ever written). Reported
/// when the session is refused up front.
fn failed_recording_outcome(object_key: &str, grant_id: &str) -> RecordingOutcome {
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

/// Open the S3 multipart upload for a required recording, keyed at `object_key`.
/// Fails when no bucket is configured or the object store rejects the
/// `CreateMultipartUpload` — either is a fail-closed trigger (refuse before dial).
async fn build_uploader(config: &Config, object_key: &str) -> anyhow::Result<S3Uploader> {
    if config.recording_bucket.is_empty() {
        anyhow::bail!("recording bucket not configured");
    }
    S3Uploader::create(
        &config.recording_s3_endpoint,
        &config.recording_s3_region,
        &config.recording_bucket,
        object_key.to_string(),
    )
    .await
}

/// Bind the data-plane mTLS listener and dispatch each accepted gateway
/// connection: TLS-accept (gateway mTLS) → read CONNECT → run the RDP bridge.
///
/// Accepts until `shutdown` fires, then stops accepting and force-closes every
/// live session in `registry` (each bridge selects on its handle's `cancel`).
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

    let listener = tokio::net::TcpListener::bind(&config.dataplane_addr)
        .await
        .with_context(|| format!("bind data-plane listener {}", config.dataplane_addr))?;
    tracing::info!(
        addr = %config.dataplane_addr,
        gateway_spiffe = %config.gateway_spiffe,
        "rdp-proxy data-plane mTLS listener ready",
    );

    loop {
        let (tcp, peer) = tokio::select! {
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
        let mesh_certs = mesh_certs.clone();
        let config = config.clone();
        let registry = registry.clone();
        let session_ended_tx = session_ended_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(
                acceptor,
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

/// Serve a minimal plaintext TCP health listener for kubelet probes (the
/// data-plane port is mesh mTLS: a bare `tcpSocket` probe against it fails the
/// TLS handshake). Accept-and-drop — the successful TCP connect is the signal.
pub async fn run_health_listener(addr: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind health listener {addr}"))?;
    tracing::info!(%addr, "rdp-proxy health listener ready");
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => drop(stream),
            Err(e) => tracing::warn!(error = %e, "health listener accept failed"),
        }
    }
}

/// Per-connection handler: gateway mTLS handshake, read the CONNECT preamble,
/// ack `200`, then run the RDP bridge (the only ingress this worker serves).
async fn handle_conn(
    acceptor: TlsAcceptor,
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

    // Acknowledge the CONNECT before bridging: the gateway blocks on this `200`
    // and blind-relays the browser's opcode frames only afterwards.
    tls.write_all(jumpgate_mesh::connect::response_established())
        .await
        .context("write CONNECT 200 response")?;
    tls.flush().await.context("flush CONNECT 200 response")?;

    // This worker serves RDP only. A preamble without `X-Jumpgate-Rdp: 1` is a
    // gateway misroute — refuse it rather than guess.
    if !req.rdp {
        tracing::warn!(%peer, authority = %req.authority, "non-RDP CONNECT reached rdp-proxy; closing");
        return Ok(());
    }
    let login = req
        .login
        .clone()
        .ok_or_else(|| anyhow::anyhow!("rdp CONNECT missing X-Jumpgate-Login header"))?;

    tracing::info!(%peer, authority = %req.authority, %login, "gateway RDP CONNECT received; starting RDP ingress");
    run_rdp(
        tls,
        login,
        req.token,
        &config,
        &mesh_certs,
        registry,
        session_ended_tx,
    )
    .await;
    Ok(())
}

/// Redeem the session with warden, register it for teardown, run the bridge, then
/// report the end. Any pre-bridge failure logs and closes the mesh stream (the
/// browser observes the WS close); the RDCleanPath bridge itself surfaces target
/// handshake failures to the browser as RDCleanPath error responses where it can.
#[allow(clippy::too_many_arguments)]
async fn run_rdp<S>(
    stream: S,
    login: String,
    token: String,
    config: &Config,
    mesh_certs: &MeshClientCerts,
    registry: SessionRegistry,
    session_ended_tx: mpsc::UnboundedSender<SessionEndReport>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Redeem the session (web mode: no client key). Any failure is a hard
    //    refuse — log and close the stream.
    let outcome = match setup_session(
        &config.warden_mesh_addr,
        &config.warden_spiffe,
        mesh_certs,
        &token,
        &config.worker_id,
        &login,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(%login, error = %e, "RDP SetupSession rejected; closing");
            return;
        }
    };

    // 2. If warden requires a recording, open the multipart upload UP FRONT —
    //    BEFORE dialing/authenticating the target. If it cannot be opened (no
    //    bucket / the object store rejects create), refuse the session: the target
    //    must never be authenticated when we cannot record.
    let uploader: Option<Box<dyn PartUploader>> = if outcome.recording_required {
        match build_uploader(config, &outcome.recording_object_key).await {
            Ok(u) => Some(Box::new(u)),
            Err(e) => {
                tracing::warn!(session_id = %outcome.session_id, error = %e, "recording unavailable; refusing session");
                let _ = session_ended_tx.send(SessionEndReport {
                    session_id: outcome.session_id.clone(),
                    reason: "recording_unavailable".into(),
                    recording: Some(failed_recording_outcome(
                        &outcome.recording_object_key,
                        &outcome.grant_id,
                    )),
                });
                return;
            }
        }
    } else {
        None
    };

    // setup_session already rejected every non-password arm, so this destructure
    // of the single-variant credential enum is infallible.
    let TargetCredential::Password(password) = &outcome.credential;

    // 3. Register the live session (so a Teardown force-closes it) and bridge. The
    //    bridge spawns the recorder after the handshake, tees each graphics frame
    //    into it (fail-closed), and finalizes it on exit.
    let handle = registry.insert(&outcome.session_id);
    tracing::info!(session_id = %outcome.session_id, %login, "RDP session set up");

    let run_report = crate::bridge::run(
        &outcome.target_address,
        &outcome.target_server_ca,
        &login,
        password,
        handle.cancel,
        stream,
        uploader,
        RecorderConfig {
            part_size: config.recording_part_size,
            channel_bound: 1024,
        },
    )
    .await;

    // 4. Exactly-once cleanup: drop from the registry, report the end (with the
    //    recording disposition) once.
    registry.remove(&outcome.session_id);
    let reason = run_report.outcome.reason();
    let recording = run_report.recording.map(|r| RecordingOutcome {
        object_key: outcome.recording_object_key.clone(),
        size_bytes: r.size_bytes,
        sha256: r.sha256_hex,
        started_at_unix_ms: run_report.started_at_unix_ms,
        ended_at_unix_ms: unix_millis_now(),
        status: match r.status {
            RecordStatus::Completed => "completed".into(),
            RecordStatus::Failed => "failed".into(),
        },
        grant_id: outcome.grant_id.clone(),
    });
    let _ = session_ended_tx.send(SessionEndReport {
        session_id: outcome.session_id.clone(),
        reason: reason.to_string(),
        recording,
    });
    tracing::info!(session_id = %outcome.session_id, reason, "RDP session ended");
}
