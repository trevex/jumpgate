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
    let config = Arc::new(russh::client::Config::default());

    let mut handle = russh::client::connect(config, target_address, TargetHandler)
        .await
        .with_context(|| format!("connect to target {target_address}"))?;

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
}
