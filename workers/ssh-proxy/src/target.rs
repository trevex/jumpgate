//! The second hop: a russh **client** to the requested target host.
//!
//! Once the client's publickey auth succeeds and the session is set up, the
//! worker dials the target over SSH and authenticates as the requested `login`
//! using the per-session key `Kw` together with the OpenSSH certificate warden
//! minted over `Kw`. The returned client handle is used to open a channel that
//! mirrors the client's (pty+shell or exec), which [`crate::proxy`] then bridges.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use russh::keys::ssh_key::{self, Certificate, PrivateKey, PublicKey};
use russh::keys::PrivateKeyWithHashAlg;

/// russh client handler for the target connection.
///
/// Its one security decision is the host-key check ([`check_server_key`]). When
/// the asset carries a configured host-key pin the handler enforces it: a target
/// whose presented host key does not match the pin is REJECTED (fail closed —
/// MITM protection). When no pin is configured the presented key is accepted and
/// its fingerprint logged (TOFU-off / accept-and-log).
///
/// [`check_server_key`]: russh::client::Handler::check_server_key
#[derive(Debug)]
pub struct TargetHandler {
    /// The asset's configured host-key pin, already parsed to the canonical
    /// public-key type. `None` = no pin configured (accept-and-log). This is
    /// pre-parsed by [`TargetHandler::new`] so a malformed pin fails closed at
    /// construction rather than accepting any key later.
    pinned_host_key: Option<PublicKey>,
}

impl TargetHandler {
    /// Build a handler for a target whose configured host-key pin is `pin` (an
    /// OpenSSH authorized_keys-style public-key line, or empty for no pin).
    ///
    /// An empty pin yields an accept-and-log handler. A non-empty pin is parsed
    /// to the canonical [`PublicKey`]; a PARSE FAILURE is an error (fail closed —
    /// a malformed pin must never silently accept an arbitrary key). Parsing here
    /// (not per-connection) surfaces a misconfigured pin before the hop begins.
    pub fn new(pin: &str) -> anyhow::Result<Self> {
        let pin = pin.trim();
        let pinned_host_key = if pin.is_empty() {
            None
        } else {
            // authorized_keys form is "<algo> <base64> [comment]"; parse to the
            // canonical PublicKey so the comparison is whitespace/comment-agnostic.
            Some(
                PublicKey::from_openssh(pin)
                    .context("parse configured target host-key pin (authorized_keys line)")?,
            )
        };
        Ok(Self { pinned_host_key })
    }
}

impl russh::client::Handler for TargetHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let presented_fp = server_public_key.fingerprint(Default::default());
        match &self.pinned_host_key {
            // No pin configured: accept the presented key and log it (TOFU-off).
            None => {
                tracing::info!(
                    fingerprint = %presented_fp,
                    algorithm = %server_public_key.algorithm(),
                    "target host key presented; accepting (no configured pin to enforce)",
                );
                Ok(true)
            }
            // Pin configured: accept ONLY on an exact key match, else fail closed.
            // Compare the canonical public-key data (algorithm + key bytes), which
            // is independent of the authorized_keys line's whitespace/comment.
            Some(pinned) => {
                if pinned.key_data() == server_public_key.key_data() {
                    tracing::info!(
                        fingerprint = %presented_fp,
                        "target host key matches configured pin; accepting",
                    );
                    Ok(true)
                } else {
                    tracing::error!(
                        expected_fingerprint = %pinned.fingerprint(Default::default()),
                        presented_fingerprint = %presented_fp,
                        "target host key does NOT match configured pin; rejecting connection (possible MITM)",
                    );
                    Ok(false)
                }
            }
        }
    }
}

/// Connect to `target_address`, enforcing the configured host-key `pin` (empty =
/// accept-and-log; see [`TargetHandler`]), and return the unauthenticated client
/// handle. The caller then runs one of the `authenticate_*` helpers.
///
/// A malformed configured pin fails CLOSED here (the connection is never
/// attempted) rather than accepting an unverified key.
async fn connect_target(
    target_address: &str,
    pin: &str,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let handler = TargetHandler::new(pin)?;
    let config = Arc::new(russh::client::Config::default());
    russh::client::connect(config, target_address, handler)
        .await
        .with_context(|| format!("connect to target {target_address}"))
}

/// Dial `target_address`, authenticate as `login` with the certificate + `Kw`,
/// and return the connected client handle.
///
/// Authentication uses SSH publickey-with-certificate: `Kw` proves possession of
/// the key the certificate was minted over, and the target's CA trust verifies
/// the certificate. The target host key is verified against `host_key_pin` when
/// non-empty, else accepted-and-logged (see [`TargetHandler`]).
pub async fn dial_target(
    target_address: &str,
    host_key_pin: &str,
    login: &str,
    kw: &PrivateKey,
    cert: &Certificate,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let mut handle = connect_target(target_address, host_key_pin).await?;

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
    host_key_pin: &str,
    login: &str,
    password: &str,
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let mut handle = connect_target(target_address, host_key_pin).await?;

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
    host_key_pin: &str,
    login: &str,
    private_key_pem: &[u8],
) -> anyhow::Result<russh::client::Handle<TargetHandler>> {
    let pem =
        std::str::from_utf8(private_key_pem).context("target private key is not valid utf-8")?;
    let key = PrivateKey::from_openssh(pem).context("parse target OpenSSH private key")?;

    let mut handle = connect_target(target_address, host_key_pin).await?;

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

    /// Generate a fresh ed25519 keypair for host-key tests.
    fn random_ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    /// (a) No pin configured → the presented host key is accepted (accept-and-log
    /// / TOFU-off), whatever it is.
    #[tokio::test]
    async fn empty_pin_accepts_any_host_key() {
        let presented = random_ed25519();
        let mut handler = TargetHandler::new("").expect("empty pin builds a handler");
        let accepted = handler
            .check_server_key(&presented.public_key().clone())
            .await
            .expect("host-key check must not error");
        assert!(accepted, "with no pin, any host key must be accepted");
    }

    /// (b) A pin that matches the presented host key → accept. The pin is supplied
    /// as an authorized_keys line WITH extra whitespace and a comment to prove the
    /// comparison is canonical (key-data), not string-based.
    #[tokio::test]
    async fn matching_pin_accepts() {
        let host = random_ed25519();
        let line = host.public_key().to_openssh().unwrap();
        // Add a trailing comment + surrounding whitespace the raw bytes wouldn't have.
        let pin = format!("  {line} host-comment  ");

        let mut handler = TargetHandler::new(&pin).expect("valid pin builds a handler");
        let accepted = handler
            .check_server_key(&host.public_key().clone())
            .await
            .expect("host-key check must not error");
        assert!(accepted, "a host key matching the pin must be accepted");
    }

    /// (c) A pin that does NOT match the presented host key → reject (Ok(false)),
    /// which russh treats as a rejected host key → the connection fails closed.
    #[tokio::test]
    async fn mismatching_pin_rejects() {
        let pinned = random_ed25519();
        let presented = random_ed25519(); // a different key
        let pin = pinned.public_key().to_openssh().unwrap();

        let mut handler = TargetHandler::new(&pin).expect("valid pin builds a handler");
        let accepted = handler
            .check_server_key(&presented.public_key().clone())
            .await
            .expect("host-key check must not error");
        assert!(
            !accepted,
            "a host key not matching the pin must be rejected (fail closed)"
        );
    }

    /// (d) A malformed configured pin → construction fails closed, so the handler
    /// is never built and no connection is attempted (a misconfigured pin must
    /// never silently accept an arbitrary key).
    #[test]
    fn malformed_pin_fails_closed() {
        let err = TargetHandler::new("this is not an authorized_keys line")
            .expect_err("a malformed pin must fail closed");
        assert!(
            err.to_string().contains("host-key pin"),
            "unexpected error: {err}"
        );
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
        let err = match authenticate_publickey("127.0.0.1:1", "", "demo", b"not a real key").await {
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
