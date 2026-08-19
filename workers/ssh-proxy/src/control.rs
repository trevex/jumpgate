//! The worker's control plane: a `dataplane/v1 WorkerStream` bidi client to
//! warden (over mesh mTLS, worker identity) plus an in-memory [`SessionRegistry`]
//! the rest of the worker uses to force-close sessions on `Teardown` and report
//! `SessionEnded`.
//!
//! ## Stream contract
//!
//! Client → server: `WorkerMessage{oneof Register|Heartbeat|SessionEnded}`.
//! Server → client: `ServerMessage{oneof RegisterAck|Teardown}`.
//! The stream's lifetime is the worker's liveness. warden derives the
//! authoritative `worker_id` from the mesh cert SAN and requires
//! `Register.worker_id == cert SAN id`.
//!
//! [`run_control`] loops forever: connect over mesh mTLS (warden pinned to
//! `config.warden_spiffe`), `Register`, heartbeat, forward `SessionEnded`, and
//! dispatch `Teardown` to the registry; on any error it backs off and reconnects.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Endpoint, Uri};

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, server_message, worker_message, Heartbeat,
    Register, ServerMessage, SessionEnded, WorkerMessage,
};
use jumpgate_mesh::tls::MeshClientCerts;

use crate::config::Config;

/// A live session's teardown handle: the proxy loop selects on `cancel.notified()`.
#[derive(Clone)]
pub struct SessionHandle {
    pub cancel: Arc<Notify>,
}

/// In-memory map of live session_id -> handle. Rebuilt implicitly on reconnect
/// (warden re-syncs via the Register live_session_ids).
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<Mutex<HashMap<String, SessionHandle>>>,
}

impl SessionRegistry {
    pub fn insert(&self, session_id: &str) -> SessionHandle {
        let h = SessionHandle {
            cancel: Arc::new(Notify::new()),
        };
        self.inner
            .lock()
            .unwrap()
            .insert(session_id.to_string(), h.clone());
        h
    }

    pub fn remove(&self, session_id: &str) {
        self.inner.lock().unwrap().remove(session_id);
    }

    /// Signal the session to tear down (if present). Returns whether it was found.
    pub fn teardown(&self, session_id: &str) -> bool {
        if let Some(h) = self.inner.lock().unwrap().get(session_id) {
            h.cancel.notify_waiters();
            true
        } else {
            false
        }
    }

    pub fn live_ids(&self) -> Vec<String> {
        self.inner.lock().unwrap().keys().cloned().collect()
    }
}

/// How often the worker sends a `Heartbeat` frame to warden.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Backoff between control-plane reconnect attempts.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
/// Bound on the outbound frame channel (Register/Heartbeat/SessionEnded).
const OUTBOUND_CHANNEL_CAP: usize = 64;

/// Runs the WorkerStream control loop forever: connects to warden over mesh
/// mTLS, Registers, sends heartbeats, forwards SessionEnded, and dispatches
/// Teardown to the registry. Reconnects with backoff. `session_ended_rx` is how
/// the data plane asks to report a finished session (session_id, reason).
pub async fn run_control(
    config: Config,
    registry: SessionRegistry,
    mut session_ended_rx: mpsc::UnboundedReceiver<(String, String)>,
) {
    // Read the worker's mesh identity PEMs once; each connect builds a cheap,
    // warden-pinned client config from them.
    let certs = match MeshClientCerts::from_files(
        &config.mesh_cert,
        &config.mesh_key,
        &config.mesh_ca,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to read worker mesh certs; control plane disabled");
            return;
        }
    };

    loop {
        match connect_and_run(&config, &certs, &registry, &mut session_ended_rx).await {
            Ok(()) => tracing::warn!("worker_stream ended; reconnecting"),
            Err(e) => tracing::warn!(error = %e, "worker_stream connection error; reconnecting"),
        }
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}

/// One control-plane session: dial warden, `Register`, then pump outbound frames
/// (heartbeats + SessionEnded) and inbound frames (RegisterAck / Teardown) until
/// the stream ends or errors.
async fn connect_and_run(
    config: &Config,
    certs: &MeshClientCerts,
    registry: &SessionRegistry,
    session_ended_rx: &mut mpsc::UnboundedReceiver<(String, String)>,
) -> anyhow::Result<()> {
    let mesh_client_config = certs
        .client_config(&config.warden_spiffe)
        .context("build warden mesh client config")?;
    let channel = mesh_channel(&config.warden_mesh_addr, mesh_client_config).await?;
    let mut client = DataplaneServiceClient::new(channel);

    // Outbound frames flow through this channel into the bidi request stream.
    let (tx, rx) = mpsc::channel::<WorkerMessage>(OUTBOUND_CHANNEL_CAP);

    // First frame MUST be Register (warden checks worker_id == cert SAN id).
    let register = WorkerMessage {
        msg: Some(worker_message::Msg::Register(Register {
            worker_id: config.worker_id.clone(),
            protocols: vec!["ssh".into()],
            capacity: config.capacity as i32,
            live_session_ids: registry.live_ids(),
            dataplane_address: config.dataplane_addr.clone(),
        })),
    };
    tx.send(register).await.context("enqueue Register frame")?;

    let mut inbound = client
        .worker_stream(ReceiverStream::new(rx))
        .await
        .context("open worker_stream")?
        .into_inner();

    tracing::info!(
        worker_id = %config.worker_id,
        warden = %config.warden_mesh_addr,
        "worker control stream established; registered",
    );

    // Heartbeat ticker: send a Heartbeat every HEARTBEAT_INTERVAL. A send error
    // means the stream is gone; we drop out and let the outer loop reconnect.
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires immediately; skip it (we just registered).
    heartbeat.tick().await;

    loop {
        tokio::select! {
            // Warden → worker: RegisterAck / Teardown.
            msg = inbound.message() => {
                match msg.context("read from worker_stream")? {
                    Some(ServerMessage { msg: Some(server_message::Msg::Teardown(t)) }) => {
                        let found = registry.teardown(&t.session_id);
                        tracing::info!(
                            session_id = %t.session_id,
                            reason = %t.reason,
                            found,
                            "teardown dispatched",
                        );
                    }
                    Some(ServerMessage { msg: Some(server_message::Msg::Ack(_)) }) => {
                        tracing::info!("register acknowledged by warden");
                    }
                    Some(ServerMessage { msg: None }) => {
                        tracing::warn!("empty ServerMessage; ignoring");
                    }
                    None => {
                        // Server closed the stream: liveness lost, reconnect.
                        return Ok(());
                    }
                }
            }

            // Heartbeat tick.
            _ = heartbeat.tick() => {
                let frame = WorkerMessage {
                    msg: Some(worker_message::Msg::Heartbeat(Heartbeat {})),
                };
                if tx.send(frame).await.is_err() {
                    // Outbound stream closed → the request half is gone.
                    return Ok(());
                }
            }

            // Data plane → warden: a finished session to report.
            ended = session_ended_rx.recv() => {
                match ended {
                    Some((session_id, reason)) => {
                        let frame = WorkerMessage {
                            msg: Some(worker_message::Msg::SessionEnded(SessionEnded {
                                session_id,
                                reason,
                            })),
                        };
                        if tx.send(frame).await.is_err() {
                            return Ok(());
                        }
                    }
                    None => {
                        // The data plane dropped its sender — the process is
                        // shutting down. End the stream cleanly.
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Build a tonic `Channel` to `warden_addr` (e.g. `https://warden-mesh:8444`)
/// that dials over mesh mTLS using the supplied rustls `ClientConfig`.
///
/// warden's mesh cert carries a URI (SPIFFE) SAN only, so tonic's built-in
/// `ClientTlsConfig` (which always webpki-name-checks) can't be used. We drive
/// the rustls handshake inside a custom connector — mirroring the gateway's
/// roster dial — and hand the resulting stream to tonic.
async fn mesh_channel(
    warden_addr: &str,
    mesh_client_config: Arc<rustls::ClientConfig>,
) -> anyhow::Result<tonic::transport::Channel> {
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioIo;
    use tokio_rustls::TlsConnector;

    let uri: Uri = warden_addr.parse().context("parse warden mesh addr")?;
    // rustls needs *some* server name for SNI; our verifier does not name-check
    // it (identity is pinned via the URI SAN instead).
    let sni: rustls::pki_types::ServerName<'static> = uri
        .host()
        .and_then(|h| rustls::pki_types::ServerName::try_from(h.to_string()).ok())
        .unwrap_or_else(|| rustls::pki_types::ServerName::try_from("warden").unwrap());

    let tls = TlsConnector::from(mesh_client_config);

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let connector = tower::service_fn(move |dst: Uri| {
        let mut http = http.clone();
        let tls = tls.clone();
        let sni = sni.clone();
        async move {
            let tcp = tower::Service::call(&mut http, dst).await?;
            let tls_stream = tls.connect(sni, TokioIo::new(tcp)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(TokioIo::new(tls_stream))
        }
    });

    let endpoint =
        Endpoint::from_shared(warden_addr.to_string()).context("build warden endpoint")?;
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .context("connect to warden mesh")?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_tracks_live_ids() {
        let reg = SessionRegistry::default();
        reg.insert("s1");
        reg.insert("s2");
        let mut ids = reg.live_ids();
        ids.sort();
        assert_eq!(ids, vec!["s1".to_string(), "s2".to_string()]);
    }

    #[tokio::test]
    async fn teardown_wakes_a_waiter_and_reports_found() {
        let reg = SessionRegistry::default();
        let handle = reg.insert("live");

        // A task awaiting the session's cancel signal.
        let waiter = tokio::spawn(async move {
            handle.cancel.notified().await;
        });
        // Give the waiter a chance to park on `notified()`.
        tokio::task::yield_now().await;

        assert!(reg.teardown("live"), "teardown should find the session");
        // The waiter must wake now that we've notified it.
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter did not wake on teardown")
            .expect("waiter task panicked");
    }

    #[test]
    fn teardown_unknown_returns_false() {
        let reg = SessionRegistry::default();
        assert!(!reg.teardown("nope"));
    }

    #[test]
    fn remove_drops_the_session() {
        let reg = SessionRegistry::default();
        reg.insert("s1");
        assert!(reg.teardown("s1"));
        reg.remove("s1");
        assert!(reg.live_ids().is_empty());
        assert!(!reg.teardown("s1"));
    }
}
