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
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use x509_parser::extensions::GeneralName;

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

/// Parse a PEM certificate chain from in-memory `pem` bytes.
fn certs_from_pem(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs from PEM bytes")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM bytes");
    }
    Ok(certs)
}

/// Parse the first PEM private key from in-memory `pem` bytes.
fn key_from_pem(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .context("parse private key from PEM bytes")?
        .context("no private key found in PEM bytes")
}

/// In-memory holder of the mesh client's PEM material. Read once at startup so
/// callers can cheaply build a per-dial [`ClientConfig`] pinned to a specific
/// peer SPIFFE identity (the worker dial needs a per-worker expected id).
#[derive(Clone)]
pub struct MeshClientCerts {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

impl MeshClientCerts {
    /// Read the mesh PEM material from disk once.
    pub fn from_files(
        cert_pem_path: &str,
        key_pem_path: &str,
        ca_pem_path: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cert_pem: fs::read(cert_pem_path)
                .with_context(|| format!("read mesh cert {cert_pem_path}"))?,
            key_pem: fs::read(key_pem_path)
                .with_context(|| format!("read mesh key {key_pem_path}"))?,
            ca_pem: fs::read(ca_pem_path).with_context(|| format!("read mesh CA {ca_pem_path}"))?,
        })
    }

    /// Build a mesh mTLS client config that verifies the peer chains to the mesh
    /// CA AND that its URI SAN equals `expected_spiffe` (see
    /// [`MeshServerCertVerifier`]).
    pub fn client_config(&self, expected_spiffe: &str) -> anyhow::Result<Arc<ClientConfig>> {
        mesh_client_config_no_hostname(&self.cert_pem, &self.key_pem, &self.ca_pem, expected_spiffe)
    }
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
/// mesh CA and is currently valid, tolerates the absence of a matching DNS/IP
/// name, but PINS the peer to a specific SPIFFE identity via its URI SAN.
///
/// WHY: warden's / a worker's mesh leaf certificate carries only a SPIFFE URI
/// SAN (`spiffe://jumpgate/warden`, `spiffe://jumpgate/worker/<id>`) and no DNS
/// SAN. tonic's built-in [`ClientTlsConfig`] (and rustls' default
/// `WebPkiServerVerifier`) always perform webpki hostname verification against
/// the requested `domain_name`, which fails with
/// `CertificateError::NotValidForName` for a URI-only cert. We still want full
/// cryptographic chain verification against the mesh CA — we only want to skip
/// the *DNS name* check. This verifier delegates chain + signature verification
/// to `WebPkiServerVerifier`, swallows *only* the `NotValidForName` outcome, and
/// then independently PARSES the end-entity certificate and requires that
/// exactly one of its URI SANs equals `expected_spiffe`.
///
/// Security: chain-to-mesh-CA alone only proves the peer is *some* mesh member —
/// it does NOT pin *which* one. The URI-SAN pin closes that gap, so the gateway
/// provably talks to the specific expected identity (`spiffe://jumpgate/warden`
/// for the roster dial, `spiffe://jumpgate/worker/<id>` for the worker dial).
/// The check fails closed: a leaf with no URI SAN, or with a mismatching URI
/// SAN, is rejected. The client also presents its own leaf for mutual auth.
/// Signature verification (`verify_tls1x_*`) is delegated unchanged.
#[derive(Debug)]
struct MeshServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    /// The SPIFFE URI the peer's end-entity cert MUST carry as a URI SAN.
    expected_spiffe: String,
}

impl MeshServerCertVerifier {
    /// Fail-closed check that the end-entity cert carries exactly one URI SAN
    /// equal to `self.expected_spiffe`.
    fn verify_spiffe_identity(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| RustlsError::General("mesh peer certificate unparseable".into()))?;

        // Collect the URI SAN(s). Fail closed if the SAN extension is absent or
        // carries no URI GeneralName.
        let san = cert
            .subject_alternative_name()
            .map_err(|_| RustlsError::General("mesh peer SAN unparseable".into()))?
            .ok_or_else(|| RustlsError::General("mesh peer has no SAN extension".into()))?;

        let uris: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect();

        // Require exactly one URI SAN, equal to the expected identity.
        if uris.len() == 1 && uris[0] == self.expected_spiffe {
            Ok(())
        } else {
            Err(RustlsError::General("mesh peer identity mismatch".into()))
        }
    }
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
        // 1. Full chain + validity verification against the mesh CA, tolerating
        //    only the missing DNS/IP name (URI-only leaf).
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            // The chain verified against the mesh CA but the leaf carries no
            // matching DNS/IP name (only a SPIFFE URI SAN). Tolerate *only* the
            // name mismatch (both the plain and context-carrying variants);
            // identity is enforced by the URI-SAN pin below.
            Err(RustlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(e) => return Err(e),
        }

        // 2. Pin the peer's SPIFFE identity via its URI SAN (fail closed).
        self.verify_spiffe_identity(end_entity)?;
        Ok(ServerCertVerified::assertion())
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

/// Build a mesh mTLS client config that verifies the chain to the mesh CA,
/// skips DNS/IP hostname verification, and PINS the peer's SPIFFE identity to
/// `expected_spiffe` via its URI SAN (see [`MeshServerCertVerifier`]).
///
/// Takes PEM *bytes* so callers can read the material once and build cheap
/// per-dial configs (the worker dial pins a per-worker identity). Used by the
/// roster tonic client (`spiffe://jumpgate/warden`) and the worker proxy dial
/// (`spiffe://jumpgate/worker/<id>`), both of which dial mesh peers whose certs
/// carry only URI SANs. Prefer [`MeshClientCerts::client_config`].
pub fn mesh_client_config_no_hostname(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    expected_spiffe: &str,
) -> anyhow::Result<Arc<ClientConfig>> {
    let certs = certs_from_pem(cert_pem)?;
    let key = key_from_pem(key_pem)?;

    let ca_certs = certs_from_pem(ca_pem)?;
    let mut roots = RootCertStore::empty();
    for ca in ca_certs {
        roots.add(ca).context("add mesh CA cert")?;
    }

    let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .context("build webpki mesh verifier")?;
    let verifier = Arc::new(MeshServerCertVerifier {
        inner: webpki,
        expected_spiffe: expected_spiffe.to_string(),
    });

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .context("build mesh client config (no hostname)")?;

    Ok(Arc::new(config))
}

/// A [`ClientCertVerifier`] (server-side mirror of [`MeshServerCertVerifier`])
/// that verifies the CLIENT's certificate chains to the mesh CA and PINS the
/// client to a specific SPIFFE identity via its URI SAN.
///
/// WHY: the ssh-proxy worker's data-plane front door accepts connections *only*
/// from the gateway. mTLS proves the peer is a mesh member (chain-to-CA), but
/// chain-to-CA alone does not pin *which* member — any mesh leaf would pass.
/// The URI-SAN pin closes that gap so the worker provably accepts only the
/// expected gateway identity (`spiffe://jumpgate/gateway/<id>`). We delegate
/// chain + signature verification to rustls' [`WebPkiClientVerifier`] and then
/// independently parse the client leaf, requiring exactly one URI SAN equal to
/// `expected_client_spiffe`. Fails closed: no URI SAN, or a mismatch, is
/// rejected. Unlike the server verifier there is no DNS/IP name check on the
/// client side, so nothing needs tolerating there.
#[derive(Debug)]
struct MeshClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    /// The SPIFFE URI the client's end-entity cert MUST carry as a URI SAN.
    expected_spiffe: String,
}

impl MeshClientCertVerifier {
    /// Fail-closed check that the end-entity cert carries exactly one URI SAN
    /// equal to `self.expected_spiffe`.
    fn verify_spiffe_identity(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| RustlsError::General("mesh peer certificate unparseable".into()))?;

        let san = cert
            .subject_alternative_name()
            .map_err(|_| RustlsError::General("mesh peer SAN unparseable".into()))?
            .ok_or_else(|| RustlsError::General("mesh peer has no SAN extension".into()))?;

        let uris: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect();

        if uris.len() == 1 && uris[0] == self.expected_spiffe {
            Ok(())
        } else {
            Err(RustlsError::General("mesh peer identity mismatch".into()))
        }
    }
}

impl ClientCertVerifier for MeshClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // 1. Full chain + validity verification against the mesh CA. Client
        //    certs carry no DNS/IP name check, so no tolerance is needed here.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        // 2. Pin the client's SPIFFE identity via its URI SAN (fail closed).
        self.verify_spiffe_identity(end_entity)?;
        Ok(ClientCertVerified::assertion())
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

/// Build a server-side rustls config that REQUIRES a client certificate chaining
/// to the mesh CA and PINS the client's SPIFFE identity to
/// `expected_client_spiffe` (e.g. `spiffe://jumpgate/gateway/<id>`) via its URI
/// SAN (see [`MeshClientCertVerifier`]).
///
/// Used by the ssh-proxy worker's data-plane front door: it accepts the
/// gateway's mesh mTLS connection and proves the peer is the expected gateway
/// identity before reading the CONNECT preamble. Takes PEM *bytes* to mirror the
/// client-side builders.
pub fn server_config_mtls(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    expected_client_spiffe: &str,
) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = certs_from_pem(cert_pem)?;
    let key = key_from_pem(key_pem)?;

    let ca_certs = certs_from_pem(ca_pem)?;
    let mut roots = RootCertStore::empty();
    for ca in ca_certs {
        roots.add(ca).context("add mesh CA cert")?;
    }

    let webpki = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build webpki mesh client verifier")?;
    let verifier = Arc::new(MeshClientCertVerifier {
        inner: webpki,
        expected_spiffe: expected_client_spiffe.to_string(),
    });

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("build server mtls config")?;

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

        let cfg = mesh_client_config_no_hostname(
            leaf.cert.pem().as_bytes(),
            leaf.key_pair.serialize_pem().as_bytes(),
            ca.cert.pem().as_bytes(),
            "spiffe://jumpgate/warden",
        );
        assert!(
            cfg.is_ok(),
            "mesh_client_config_no_hostname failed: {:?}",
            cfg.err()
        );
    }

    #[test]
    fn mesh_client_certs_from_files_and_client_config() {
        let ca = rcgen::generate_simple_self_signed(vec!["mesh-ca".to_string()]).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["gateway".to_string()]).unwrap();

        let ca_pem = write_pem(&ca.cert.pem());
        let leaf_cert_pem = write_pem(&leaf.cert.pem());
        let leaf_key_pem = write_pem(&leaf.key_pair.serialize_pem());

        let certs = MeshClientCerts::from_files(
            leaf_cert_pem.path().to_str().unwrap(),
            leaf_key_pem.path().to_str().unwrap(),
            ca_pem.path().to_str().unwrap(),
        )
        .unwrap();
        assert!(certs.client_config("spiffe://jumpgate/worker/w1").is_ok());
    }

    /// Build a leaf whose only SAN is the given SPIFFE URI, signed by `ca`.
    fn spiffe_leaf(
        ca_cert: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
        spiffe: &str,
    ) -> rcgen::Certificate {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(spiffe.try_into().unwrap())];
        let key = rcgen::KeyPair::generate().unwrap();
        params.signed_by(&key, ca_cert, ca_key).unwrap()
    }

    /// A self-signed CA: returns (cert, key, ca_pem).
    fn test_ca() -> (rcgen::Certificate, rcgen::KeyPair, String) {
        let mut params = rcgen::CertificateParams::new(vec!["mesh-ca".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let ca_pem = cert.pem();
        (cert, key, ca_pem)
    }

    fn build_verifier(ca_pem: &str, expected: &str) -> MeshServerCertVerifier {
        let mut roots = RootCertStore::empty();
        for c in certs_from_pem(ca_pem.as_bytes()).unwrap() {
            roots.add(c).unwrap();
        }
        let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        MeshServerCertVerifier {
            inner: webpki,
            expected_spiffe: expected.to_string(),
        }
    }

    #[test]
    fn verifier_accepts_matching_spiffe() {
        let (ca, ca_key, ca_pem) = test_ca();
        let leaf = spiffe_leaf(&ca, &ca_key, "spiffe://jumpgate/worker/w1");
        let v = build_verifier(&ca_pem, "spiffe://jumpgate/worker/w1");
        let der = CertificateDer::from(leaf.der().to_vec());
        assert!(v.verify_spiffe_identity(&der).is_ok());
    }

    #[test]
    fn verifier_rejects_mismatched_spiffe() {
        let (ca, ca_key, ca_pem) = test_ca();
        let leaf = spiffe_leaf(&ca, &ca_key, "spiffe://jumpgate/worker/w2");
        let v = build_verifier(&ca_pem, "spiffe://jumpgate/worker/w1");
        let der = CertificateDer::from(leaf.der().to_vec());
        assert!(v.verify_spiffe_identity(&der).is_err());
    }

    #[test]
    fn verifier_rejects_no_uri_san() {
        let (ca, ca_key, ca_pem) = test_ca();
        // Leaf with a DNS SAN but no URI SAN -> fail closed.
        let mut params = rcgen::CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        params.subject_alt_names =
            vec![rcgen::SanType::DnsName("host.example".try_into().unwrap())];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let v = build_verifier(&ca_pem, "spiffe://jumpgate/worker/w1");
        let der = CertificateDer::from(cert.der().to_vec());
        assert!(v.verify_spiffe_identity(&der).is_err());
    }

    fn build_client_verifier(ca_pem: &str, expected: &str) -> MeshClientCertVerifier {
        let mut roots = RootCertStore::empty();
        for c in certs_from_pem(ca_pem.as_bytes()).unwrap() {
            roots.add(c).unwrap();
        }
        let webpki = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        MeshClientCertVerifier {
            inner: webpki,
            expected_spiffe: expected.to_string(),
        }
    }

    #[test]
    fn client_verifier_accepts_matching_gateway_spiffe() {
        let (ca, ca_key, ca_pem) = test_ca();
        let leaf = spiffe_leaf(&ca, &ca_key, "spiffe://jumpgate/gateway/gw");
        let v = build_client_verifier(&ca_pem, "spiffe://jumpgate/gateway/gw");
        let der = CertificateDer::from(leaf.der().to_vec());
        assert!(v.verify_spiffe_identity(&der).is_ok());
    }

    #[test]
    fn client_verifier_rejects_wrong_role_spiffe() {
        let (ca, ca_key, ca_pem) = test_ca();
        // A worker identity must NOT be accepted where a gateway is expected.
        let leaf = spiffe_leaf(&ca, &ca_key, "spiffe://jumpgate/worker/w1");
        let v = build_client_verifier(&ca_pem, "spiffe://jumpgate/gateway/gw");
        let der = CertificateDer::from(leaf.der().to_vec());
        assert!(v.verify_spiffe_identity(&der).is_err());
    }

    #[test]
    fn client_verifier_rejects_wrong_ca() {
        // Leaf minted under a DIFFERENT CA than the verifier trusts. Even with a
        // matching SPIFFE id, the full verify_client_cert must fail at the chain
        // step (the standalone identity check passes, so exercise the chain).
        let (other_ca, other_ca_key, _other_ca_pem) = test_ca();
        let leaf = spiffe_leaf(&other_ca, &other_ca_key, "spiffe://jumpgate/gateway/gw");
        // Verifier trusts a fresh, unrelated CA.
        let (_trusted_ca, _trusted_key, trusted_ca_pem) = test_ca();
        let v = build_client_verifier(&trusted_ca_pem, "spiffe://jumpgate/gateway/gw");
        let der = CertificateDer::from(leaf.der().to_vec());
        let now = rustls::pki_types::UnixTime::now();
        assert!(v.verify_client_cert(&der, &[], now).is_err());
    }

    #[test]
    fn server_config_mtls_builds() {
        let (ca, ca_key, ca_pem) = test_ca();
        // The worker's own server leaf: matching cert + key signed by the CA.
        let mut params = rcgen::CertificateParams::new(vec!["worker".to_string()]).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://jumpgate/worker/w1".try_into().unwrap(),
        )];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();

        let cfg = server_config_mtls(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            ca_pem.as_bytes(),
            "spiffe://jumpgate/gateway/gw",
        );
        assert!(cfg.is_ok(), "server_config_mtls failed: {:?}", cfg.err());
    }

    #[test]
    fn missing_cert_file_errors() {
        let err = server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(err.is_err());
    }
}
