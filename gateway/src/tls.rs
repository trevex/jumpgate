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
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

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
    fn missing_cert_file_errors() {
        let err = server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(err.is_err());
    }
}
