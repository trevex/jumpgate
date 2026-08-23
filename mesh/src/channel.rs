//! Shared mesh tonic-`Channel` construction: dial a warden/mesh peer over the
//! custom mesh mTLS connector and hand the resulting stream to tonic.
//!
//! ## Why a custom connector
//!
//! Mesh leaf certificates carry a SPIFFE URI SAN only (no DNS name), so tonic's
//! built-in `ClientTlsConfig` — which always performs webpki hostname
//! verification against the configured `domain_name` — cannot be used; it would
//! reject the cert with `NotValidForName`. Instead we drive the rustls handshake
//! ourselves inside a `tower::service_fn` connector (using a
//! [`crate::tls::MeshClientCerts`]-derived `ClientConfig` whose verifier pins the
//! peer's URI SAN), and hand the resulting stream to tonic via
//! [`Endpoint::connect_with_connector`].
//!
//! Shared by the gateway's roster dial and the ssh-proxy worker's control /
//! setup dials, all of which build this exact channel.

use std::sync::Arc;

use anyhow::Context;
use tonic::transport::{Channel, Endpoint, Uri};

/// Build a tonic [`Channel`] to `warden_addr` (e.g. `https://warden-mesh:8444`)
/// that dials over mesh mTLS using the supplied rustls `ClientConfig`.
///
/// `mesh_client_config` is expected to be a mesh client config that pins the
/// peer's SPIFFE identity via its URI SAN (see
/// [`crate::tls::MeshClientCerts::client_config`]). TLS is handled entirely by
/// the custom connector, so the tonic endpoint is presented with an `http`
/// scheme (see [`http_scheme`]); the connector still dials the same host:port
/// and wraps it in mesh TLS.
pub async fn mesh_channel(
    warden_addr: &str,
    mesh_client_config: Arc<rustls::ClientConfig>,
) -> anyhow::Result<Channel> {
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioIo;
    use tokio_rustls::TlsConnector;

    let uri: Uri = warden_addr.parse().context("parse mesh addr")?;
    // The rustls handshake needs *some* server name; it is only used for SNI and
    // is not name-checked by our verifier (identity is pinned via the URI SAN
    // instead). Use the URI host or a fixed label.
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
            // The mesh RPCs are gRPC over HTTP/2. tonic decides h1-vs-h2 from the
            // connector's reported ALPN; wrapping the TLS stream in a plain
            // TokioIo loses that, so tonic falls back to HTTP/1.1 and the
            // handshake never completes. Report h2 explicitly.
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(H2Stream(TokioIo::new(tls_stream)))
        }
    });

    // tonic refuses an `https://` origin unless its own ClientTlsConfig is set;
    // TLS is handled entirely by the custom connector above, so present the
    // endpoint (and the `dst` URI it hands the connector) with an `http` scheme.
    // The connector still dials the same host:port and wraps it in mesh TLS.
    let endpoint = Endpoint::from_shared(http_scheme(warden_addr)).context("build mesh endpoint")?;
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .context("connect to mesh peer")?;
    Ok(channel)
}

/// Rewrite an `https://…` address to `http://…` (leaving other schemes intact).
/// Used to build the tonic endpoint origin when TLS is handled by a custom
/// connector rather than tonic's own ClientTlsConfig.
pub fn http_scheme(addr: &str) -> String {
    match addr.strip_prefix("https://") {
        Some(rest) => format!("http://{rest}"),
        None => addr.to_string(),
    }
}

/// An IO wrapper whose `Connection::connected()` reports negotiated HTTP/2, so
/// tonic drives the mesh gRPC channel over h2 (see [`mesh_channel`]'s
/// connector). It delegates all IO to the inner hyper-compatible stream.
pub struct H2Stream<T>(pub T);

impl<T> hyper_util::client::legacy::connect::Connection for H2Stream<T> {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new().negotiated_h2()
    }
}

impl<T: hyper::rt::Read + Unpin> hyper::rt::Read for H2Stream<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<T: hyper::rt::Write + Unpin> hyper::rt::Write for H2Stream<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_scheme_rewrites_https() {
        assert_eq!(http_scheme("https://warden-mesh:8444"), "http://warden-mesh:8444");
    }

    #[test]
    fn http_scheme_leaves_http_and_others_intact() {
        assert_eq!(http_scheme("http://warden-mesh:8444"), "http://warden-mesh:8444");
        assert_eq!(http_scheme("warden-mesh:8444"), "warden-mesh:8444");
    }
}
