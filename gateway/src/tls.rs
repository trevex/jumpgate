//! rustls TLS configuration loaders for the gateway.
//!
//! Two configs are built from PEM files on disk:
//!   * [`server_config`] — the external server TLS listener (no client auth).
//!   * [`mesh_client_config`] — the internal mesh mTLS client, reused by the
//!     tonic roster client (Task 10) and the worker proxy dial (Task 12).
//!
//! The custom mesh certificate verifiers (mesh leaves carry URI SANs only, no
//! DNS) land in Tasks 10/12; here we build the standard configs.

use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};

/// Read and parse a PEM certificate chain from `path`.
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).with_context(|| format!("open cert file {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certs from {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

/// Read and parse the first PEM private key from `path`.
fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("open key file {path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key from {path}"))?
        .with_context(|| format!("no private key found in {path}"))
}

/// Build the external server TLS config (no client authentication).
pub fn server_config(cert_pem_path: &str, key_pem_path: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_pem_path)?;
    let key = load_key(key_pem_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build server config")?;
    // The external client speaks HTTP/1.1 CONNECT over TLS.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Build the internal mesh mTLS client config.
///
/// The root store is populated from the mesh CA bundle; the client presents its
/// own leaf certificate + key for mutual authentication.
pub fn mesh_client_config(
    cert_pem_path: &str,
    key_pem_path: &str,
    ca_pem_path: &str,
) -> anyhow::Result<Arc<ClientConfig>> {
    let certs = load_certs(cert_pem_path)?;
    let key = load_key(key_pem_path)?;

    let ca_certs = load_certs(ca_pem_path)?;
    let mut roots = RootCertStore::empty();
    for ca in ca_certs {
        roots
            .add(ca)
            .with_context(|| format!("add mesh CA cert from {ca_pem_path}"))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build mesh client config")?;

    Ok(Arc::new(config))
}

/// A [`ServerCertVerifier`] that verifies the peer's certificate chains to the
/// mesh CA and is currently valid, but tolerates the absence of a matching
/// DNS/IP name in the certificate.
///
/// WHY: warden's mesh leaf certificates carry only a SPIFFE URI SAN
/// (`spiffe://jumpgate/warden`) and no DNS SAN. tonic's built-in
/// [`ClientTlsConfig`] (and rustls' default `WebPkiServerVerifier`) always
/// perform webpki hostname verification against the requested `domain_name`,
/// which fails with `CertificateError::NotValidForName` for a URI-only cert. We
/// still want full cryptographic chain verification against the mesh CA — we
/// only want to skip the *name* check. This verifier delegates everything to
/// `WebPkiServerVerifier` and swallows *only* the `NotValidForName` outcome.
///
/// This does NOT weaken authentication in the mesh: the mesh CA is a private CA
/// that issues certs solely to mesh peers, and the client presents its own leaf
/// for mutual auth. Identity beyond "signed by the mesh CA" (i.e. the SPIFFE URI
/// SAN) is enforced server-side; the gateway only dials warden, whose identity
/// is pinned by the CA trust anchor. Signature verification (`verify_tls1x_*`)
/// is delegated unchanged.
// Constructed by `mesh_client_config_no_hostname`, which is wired into the
// roster client / worker dial in Tasks 12/13.
#[allow(dead_code)]
#[derive(Debug)]
struct MeshServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for MeshServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            // The chain verified against the mesh CA but the leaf carries no
            // matching DNS/IP name (only a SPIFFE URI SAN). Accept it — the
            // chain-to-CA guarantee is what authenticates the mesh peer.
            Err(RustlsError::InvalidCertificate(CertificateError::NotValidForName)) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a mesh mTLS client config that verifies the chain to the mesh CA but
/// skips DNS/IP hostname verification (see [`MeshServerCertVerifier`]).
///
/// Used by the roster tonic client (Task 10) and the worker proxy dial
/// (Task 12), both of which dial mesh peers whose certs carry only URI SANs.
// Wired into the roster client / worker dial in Tasks 12/13.
#[allow(dead_code)]
pub fn mesh_client_config_no_hostname(
    cert_pem_path: &str,
    key_pem_path: &str,
    ca_pem_path: &str,
) -> anyhow::Result<Arc<ClientConfig>> {
    let certs = load_certs(cert_pem_path)?;
    let key = load_key(key_pem_path)?;

    let ca_certs = load_certs(ca_pem_path)?;
    let mut roots = RootCertStore::empty();
    for ca in ca_certs {
        roots
            .add(ca)
            .with_context(|| format!("add mesh CA cert from {ca_pem_path}"))?;
    }

    let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build webpki mesh verifier")?;
    let verifier = Arc::new(MeshServerCertVerifier { inner: webpki });

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .context("build mesh client config (no hostname)")?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_pem(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn server_config_loads_self_signed() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = write_pem(&cert.cert.pem());
        let key_pem = write_pem(&cert.key_pair.serialize_pem());

        let cfg = server_config(
            cert_pem.path().to_str().unwrap(),
            key_pem.path().to_str().unwrap(),
        );
        assert!(cfg.is_ok(), "server_config failed: {:?}", cfg.err());
    }

    #[test]
    fn mesh_client_config_loads_ca_and_leaf() {
        // A CA-ish cert used as the trust root.
        let ca = rcgen::generate_simple_self_signed(vec!["mesh-ca".to_string()]).unwrap();
        // A separate self-signed leaf used as the client identity.
        let leaf = rcgen::generate_simple_self_signed(vec!["gateway".to_string()]).unwrap();

        let ca_pem = write_pem(&ca.cert.pem());
        let leaf_cert_pem = write_pem(&leaf.cert.pem());
        let leaf_key_pem = write_pem(&leaf.key_pair.serialize_pem());

        let cfg = mesh_client_config(
            leaf_cert_pem.path().to_str().unwrap(),
            leaf_key_pem.path().to_str().unwrap(),
            ca_pem.path().to_str().unwrap(),
        );
        assert!(cfg.is_ok(), "mesh_client_config failed: {:?}", cfg.err());
    }

    #[test]
    fn mesh_client_config_no_hostname_builds() {
        let ca = rcgen::generate_simple_self_signed(vec!["mesh-ca".to_string()]).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["gateway".to_string()]).unwrap();

        let ca_pem = write_pem(&ca.cert.pem());
        let leaf_cert_pem = write_pem(&leaf.cert.pem());
        let leaf_key_pem = write_pem(&leaf.key_pair.serialize_pem());

        let cfg = mesh_client_config_no_hostname(
            leaf_cert_pem.path().to_str().unwrap(),
            leaf_key_pem.path().to_str().unwrap(),
            ca_pem.path().to_str().unwrap(),
        );
        assert!(
            cfg.is_ok(),
            "mesh_client_config_no_hostname failed: {:?}",
            cfg.err()
        );
    }

    #[test]
    fn missing_cert_file_errors() {
        let err = server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(err.is_err());
    }
}
