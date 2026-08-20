//! The second hop: a russh **client** to the requested target host.
//!
//! Once the client's publickey auth succeeds and the session is set up, the
//! worker dials the target over SSH and authenticates as the requested `login`
//! using the per-session key `Kw` together with the OpenSSH certificate warden
//! minted over `Kw`. The returned client handle is used to open a channel that
//! mirrors the client's (pty+shell or exec), which [`crate::proxy`] then bridges.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use russh::keys::ssh_key::{self, Certificate, PrivateKey};
use russh::keys::PrivateKeyWithHashAlg;

/// russh client handler for the target connection.
///
/// The only decision it makes today is the host-key check. warden does not yet
/// return the asset's configured host key, so the presented key is accepted and
/// its fingerprint logged; enforcing a configured pin is a future enhancement
/// once the key is available on the session.
pub struct TargetHandler;

impl russh::client::Handler for TargetHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        tracing::info!(
            fingerprint = %server_public_key.fingerprint(Default::default()),
            algorithm = %server_public_key.algorithm(),
            "target host key presented; accepting (no configured pin to enforce yet)",
        );
        Ok(true)
    }
}

/// Connect to `target_address` (host-key accepted-and-logged; see
/// [`TargetHandler`]) and return the unauthenticated client handle. The caller
/// then runs one of the `authenticate_*` helpers.
async fn connect_target(
    target_address: &str,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let config = Arc::new(russh::client::Config::default());
    russh::client::connect(config, target_address, TargetHandler)
        .await
        .with_context(|| format!("connect to target {target_address}"))
}

/// Dial `target_address`, authenticate as `login` with the certificate + `Kw`,
/// and return the connected client handle.
///
/// Authentication uses SSH publickey-with-certificate: `Kw` proves possession of
/// the key the certificate was minted over, and the target's CA trust verifies
/// the certificate. The host key is accepted-and-logged (see [`TargetHandler`]).
pub async fn dial_target(
    target_address: &str,
    login: &str,
    kw: &PrivateKey,
    cert: &Certificate,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let mut handle = connect_target(target_address).await?;

    let auth = handle
        .authenticate_openssh_cert(login, Arc::new(kw.clone()), cert.clone())
        .await
        .context("target certificate authentication")?;

    if !auth.success() {
        return Err(anyhow!(
            "target rejected certificate authentication for login {login:?}"
        ));
    }

    tracing::info!(%target_address, %login, "authenticated to target with session certificate");
    Ok(handle)
}

/// Dial `target_address` and authenticate as `login` with a plain stored
/// `password` (the `password` login kind). Returns the connected handle.
///
/// The password is warden-injected and never reaches the client. A rejected auth
/// (or transport failure) is an error the caller MUST treat as a hard reject.
pub async fn authenticate_password(
    target_address: &str,
    login: &str,
    password: &str,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let mut handle = connect_target(target_address).await?;

    let auth = handle
        .authenticate_password(login, password.to_string())
        .await
        .context("target password authentication")?;

    if !auth.success() {
        return Err(anyhow!(
            "target rejected password authentication for login {login:?}"
        ));
    }

    tracing::info!(%target_address, %login, "authenticated to target with stored password");
    Ok(handle)
}

/// Dial `target_address` and authenticate as `login` with a plain stored OpenSSH
/// private key (`private_key_pem`, the `key` login kind). Returns the connected
/// handle.
///
/// The PEM is parsed with [`PrivateKey::from_openssh`]; a parse failure, a
/// rejected auth, or a transport failure is an error the caller MUST treat as a
/// hard reject. The key is warden-injected and never reaches the client.
pub async fn authenticate_publickey(
    target_address: &str,
    login: &str,
    private_key_pem: &[u8],
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let pem =
        std::str::from_utf8(private_key_pem).context("target private key is not valid utf-8")?;
    let key = PrivateKey::from_openssh(pem).context("parse target OpenSSH private key")?;

    let mut handle = connect_target(target_address).await?;

    let auth = handle
        .authenticate_publickey(login, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .context("target publickey authentication")?;

    if !auth.success() {
        return Err(anyhow!(
            "target rejected publickey authentication for login {login:?}"
        ));
    }

    tracing::info!(%target_address, %login, "authenticated to target with stored private key");
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler as _;
    use russh::keys::ssh_key::Algorithm;

    #[tokio::test]
    async fn host_key_is_accepted_and_logged() {
        // Until warden returns the asset's configured host key, the presented
        // key is accepted (and its fingerprint logged) so the hop can proceed.
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut handler = TargetHandler;
        let accepted = handler
            .check_server_key(&key.public_key().clone())
            .await
            .expect("host-key check must not error");
        assert!(accepted, "host key must be accepted");
    }

    /// A well-formed OpenSSH private-key PEM round-trips through the parser the
    /// publickey path uses (`PrivateKey::from_openssh`). We don't stand up a live
    /// target here; the parse is the isolatable, fail-closed step.
    #[test]
    fn valid_openssh_private_key_pem_parses() {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(Default::default()).unwrap();
        let parsed = PrivateKey::from_openssh(pem.as_str()).expect("valid PEM must parse");
        assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
    }

    /// A garbage private-key PEM is rejected before any connection is attempted,
    /// so `authenticate_publickey` fails closed on a malformed injected key.
    #[tokio::test]
    async fn garbage_private_key_pem_is_rejected() {
        let err = match authenticate_publickey("127.0.0.1:1", "demo", b"not a real key").await {
            Ok(_) => panic!("garbage PEM must not authenticate"),
            Err(e) => e,
        };
        // The parse error surfaces (we never reach the connect step).
        assert!(
            err.to_string().contains("private key"),
            "unexpected error: {err}"
        );
    }
}
