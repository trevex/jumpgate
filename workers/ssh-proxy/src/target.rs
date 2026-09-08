//! The second hop: a russh **client** to the requested target host, split into
//! connect-and-observe then authenticate so the credential is never presented to
//! an unverified target.
//!
//! [`connect_observe`] runs the transport handshake (banner + KEX + host-key
//! check) and returns the connected handle together with the host key the target
//! presented — WITHOUT sending any user-auth. The caller (see [`crate::server`])
//! matches that observed key against warden's approved trust anchors, and ONLY on
//! a match does it obtain a credential and call one of the `authenticate_*_on`
//! helpers on the same handle. On a mismatch the handle is dropped with no
//! credential ever released.
//!
//! ## No accept-any, no per-asset pin
//!
//! [`check_server_key`](russh::client::Handler::check_server_key) here observes
//! and accepts every host key — it makes NO trust decision. The trust decision is
//! the explicit anchor match the caller performs against the observed key after
//! the handshake, which fails closed when nothing matches (an unknown target is
//! refused, never accepted-and-logged).

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context};
use russh::keys::ssh_key::{self, Certificate, PrivateKey, PublicKey};
use russh::keys::PrivateKeyWithHashAlg;

/// russh client handler for the target connection. It captures the presented host
/// key and accepts it; it makes NO trust decision (the caller matches the captured
/// key against approved anchors after the handshake — see the module docs).
#[derive(Debug, Default)]
pub struct TargetHandler {
    observed: Arc<Mutex<Option<PublicKey>>>,
}

impl russh::client::Handler for TargetHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Observe only. The security decision is the caller's anchor match; here
        // we snapshot the key so the caller can compare its fingerprint and decide.
        *self.observed.lock().unwrap() = Some(server_public_key.clone());
        Ok(true)
    }
}

/// Connect to `target_address` and run the transport handshake (KEX + host-key
/// exchange), returning the connected client handle and the host key the target
/// presented. NO user-auth is sent: the caller must match the observed key against
/// an approved trust anchor and obtain a credential before authenticating.
///
/// russh's `connect` returns after KEX + `check_server_key` but before any
/// `authenticate_*`, so the returned handle is connected-but-unauthenticated.
pub async fn connect_observe(
    target_address: &str,
) -> anyhow::Result<(russh::client::Handle<TargetHandler>, PublicKey)> {
    let observed: Arc<Mutex<Option<PublicKey>>> = Arc::new(Mutex::new(None));
    let handler = TargetHandler {
        observed: observed.clone(),
    };
    let config = Arc::new(russh::client::Config::default());
    let handle = russh::client::connect(config, target_address, handler)
        .await
        .with_context(|| format!("connect to target {target_address}"))?;

    let host_key = observed
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow!("target presented no host key during key exchange"))?;
    Ok((handle, host_key))
}

/// Authenticate an already-connected `handle` as `login` with the certificate +
/// `Kw` (the ca login kind). `Kw` proves possession of the key the certificate was
/// minted over; the target's CA trust verifies the certificate.
pub async fn authenticate_cert_on(
    handle: &mut russh::client::Handle<TargetHandler>,
    login: &str,
    kw: &PrivateKey,
    cert: &Certificate,
) -> anyhow::Result<()> {
    let auth = handle
        .authenticate_openssh_cert(login, Arc::new(kw.clone()), cert.clone())
        .await
        .context("target certificate authentication")?;
    if !auth.success() {
        return Err(anyhow!(
            "target rejected certificate authentication for login {login:?}"
        ));
    }
    tracing::info!(%login, "authenticated to verified target with session certificate");
    Ok(())
}

/// Authenticate an already-connected `handle` as `login` with a plain stored
/// `password` (the `password` login kind). The password is warden-injected and
/// never reaches the client.
pub async fn authenticate_password_on(
    handle: &mut russh::client::Handle<TargetHandler>,
    login: &str,
    password: &str,
) -> anyhow::Result<()> {
    let auth = handle
        .authenticate_password(login, password.to_string())
        .await
        .context("target password authentication")?;
    if !auth.success() {
        return Err(anyhow!(
            "target rejected password authentication for login {login:?}"
        ));
    }
    tracing::info!(%login, "authenticated to verified target with stored password");
    Ok(())
}

/// Authenticate an already-connected `handle` as `login` with a plain stored
/// OpenSSH private key (`private_key_pem`, the `key` login kind). A PEM parse
/// failure, a rejected auth, or a transport failure is an error. The key is
/// warden-injected and never reaches the client.
pub async fn authenticate_publickey_on(
    handle: &mut russh::client::Handle<TargetHandler>,
    login: &str,
    private_key_pem: &[u8],
) -> anyhow::Result<()> {
    let pem =
        std::str::from_utf8(private_key_pem).context("target private key is not valid utf-8")?;
    let key = PrivateKey::from_openssh(pem).context("parse target OpenSSH private key")?;

    let auth = handle
        .authenticate_publickey(login, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .context("target publickey authentication")?;
    if !auth.success() {
        return Err(anyhow!(
            "target rejected publickey authentication for login {login:?}"
        ));
    }
    tracing::info!(%login, "authenticated to verified target with stored private key");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::Algorithm;

    /// A well-formed OpenSSH private-key PEM round-trips through the parser the
    /// publickey path uses (`PrivateKey::from_openssh`). The parse is the
    /// isolatable, fail-closed step before any auth is attempted.
    #[test]
    fn valid_openssh_private_key_pem_parses() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(Default::default()).unwrap();
        let parsed = PrivateKey::from_openssh(pem.as_str()).expect("valid PEM must parse");
        assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
    }
}
