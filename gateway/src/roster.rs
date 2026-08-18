//! The worker roster: subscribes to warden's GatewayService.WatchWorkers over mesh
//! mTLS and maintains a shared worker_id -> WorkerEntry map. Reconnects on drop.
//!
//! ## mTLS to warden (URI-SAN certs)
//!
//! warden's mesh server certificate carries only a SPIFFE URI SAN
//! (`spiffe://jumpgate/warden/<id>`, canonically `spiffe://jumpgate/warden/warden`)
//! and no DNS SAN, so tonic's built-in
//! `ClientTlsConfig` (which always does webpki hostname verification against the
//! configured `domain_name`) cannot be used — it would reject the cert with
//! `NotValidForName`. Instead we build a custom hyper-util based connector that
//! performs the rustls handshake using [`tls::mesh_client_config_no_hostname`],
//! whose verifier still verifies the full chain to the mesh CA but tolerates the
//! missing DNS name. That rustls `ClientConfig` is handed to tonic via
//! [`Endpoint::connect_with_connector`]. See `tls::MeshServerCertVerifier` for
//! the security rationale.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tonic::transport::{Endpoint, Uri};

use crate::tls::MeshClientCerts;

use crate::pb::jumpgate::gateway::v1::{
    gateway_service_client::GatewayServiceClient, roster_event::Kind,
    GetSessionVerificationKeyRequest, WatchWorkersRequest,
};

#[derive(Clone, Debug)]
pub struct WorkerEntry {
    pub worker_id: String,
    pub protocol: String,
    pub address: String,
    pub capacity: i32,
}

#[derive(Clone, Default)]
pub struct Roster {
    inner: Arc<RwLock<HashMap<String, WorkerEntry>>>,
}

impl Roster {
    pub fn apply_added(&self, worker_id: &str, protocol: &str, address: &str, capacity: i32) {
        self.inner.write().unwrap().insert(
            worker_id.to_string(),
            WorkerEntry {
                worker_id: worker_id.to_string(),
                protocol: protocol.to_string(),
                address: address.to_string(),
                capacity,
            },
        );
    }

    pub fn apply_removed(&self, worker_id: &str) {
        self.inner.write().unwrap().remove(worker_id);
    }

    /// All workers serving `protocol`.
    pub fn snapshot_for(&self, protocol: &str) -> Vec<WorkerEntry> {
        self.inner
            .read()
            .unwrap()
            .values()
            .filter(|e| e.protocol == protocol)
            .cloned()
            .collect()
    }
}

/// Connect to warden's GatewayService over mesh mTLS and stream roster updates into
/// `roster` forever, reconnecting with backoff. On each successful connect it also
/// fetches the session verification key and hands the bytes to `on_key`.
pub async fn run(
    roster: Roster,
    warden_addr: String,
    warden_spiffe: String,
    certs: MeshClientCerts,
    on_key: impl Fn(Vec<u8>) + Send + Sync + 'static,
) {
    // Build the warden-pinned mesh config once (URI SAN == the configured warden id,
    // canonically spiffe://jumpgate/warden/warden).
    let mesh_client_config = match certs.client_config(&warden_spiffe) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to build warden mesh client config");
            return;
        }
    };
    loop {
        match connect_and_stream(&roster, &warden_addr, mesh_client_config.clone(), &on_key).await {
            Ok(()) => tracing::warn!("watch_workers stream ended; reconnecting"),
            Err(e) => tracing::warn!(error = %e, "watch_workers connection error; reconnecting"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Build a mesh-mTLS tonic `Channel`, fetch the session verification key once,
/// then stream `WatchWorkers` into `roster` until the stream ends or errors.
async fn connect_and_stream(
    roster: &Roster,
    warden_addr: &str,
    mesh_client_config: Arc<rustls::ClientConfig>,
    on_key: &(impl Fn(Vec<u8>) + Send + Sync + 'static),
) -> anyhow::Result<()> {
    let channel = mesh_channel(warden_addr, mesh_client_config).await?;
    let mut client = GatewayServiceClient::new(channel);

    // Fetch the session-token verification key on (re)connect.
    let key = client
        .get_session_verification_key(GetSessionVerificationKeyRequest {})
        .await?
        .into_inner()
        .ed25519_public_key;
    on_key(key);

    let mut stream = client
        .watch_workers(WatchWorkersRequest {})
        .await?
        .into_inner();

    while let Some(ev) = stream.message().await? {
        match ev.kind() {
            Kind::Added => {
                if let Some(w) = ev.worker {
                    roster.apply_added(&w.worker_id, &w.protocol, &w.dataplane_address, w.capacity);
                }
            }
            Kind::Removed => {
                if let Some(w) = ev.worker {
                    roster.apply_removed(&w.worker_id);
                }
            }
            Kind::Unspecified => {
                tracing::warn!("received roster event with unspecified kind; ignoring");
            }
        }
    }

    Ok(())
}

/// Build a tonic `Channel` to `warden_addr` (e.g. `https://warden-mesh:8444`)
/// that dials over mesh mTLS using the supplied rustls `ClientConfig`.
///
/// We can't use tonic's `ClientTlsConfig` because warden's mesh cert has no DNS
/// SAN (URI-only). Instead we drive the rustls handshake ourselves inside a
/// custom connector and hand the resulting stream to tonic.
async fn mesh_channel(
    warden_addr: &str,
    mesh_client_config: Arc<rustls::ClientConfig>,
) -> anyhow::Result<tonic::transport::Channel> {
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioIo;
    use tokio_rustls::TlsConnector;

    let uri: Uri = warden_addr.parse()?;
    // The rustls handshake needs *some* server name; it is only used for SNI and
    // is not name-checked by our verifier. Use the URI host or a fixed label.
    let sni: rustls::pki_types::ServerName<'static> = uri
        .host()
        .and_then(|h| rustls::pki_types::ServerName::try_from(h.to_string()).ok())
        .unwrap_or_else(|| rustls::pki_types::ServerName::try_from("warden").unwrap());

    let tls = TlsConnector::from(mesh_client_config);

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    // A connector: Service<Uri> -> TLS-wrapped, HTTP/2-capable IO for tonic.
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

    let endpoint = Endpoint::from_shared(warden_addr.to_string())?;
    let channel = endpoint.connect_with_connector(connector).await?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_add_remove_and_snapshot() {
        let r = Roster::default();
        r.apply_added("w1", "ssh", "10.0.0.1:9000", 10);
        r.apply_added("w2", "ssh", "10.0.0.2:9000", 5);
        r.apply_added("wp", "postgres", "10.0.0.3:9000", 5);
        let ssh = r.snapshot_for("ssh");
        assert_eq!(ssh.len(), 2);
        r.apply_removed("w1");
        let ssh = r.snapshot_for("ssh");
        assert_eq!(ssh.len(), 1);
        assert_eq!(ssh[0].worker_id, "w2");
        assert!(r.snapshot_for("nope").is_empty());
    }
}
