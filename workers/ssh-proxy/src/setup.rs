//! The worker's SetupSession client: redeem a session token against warden over
//! mesh mTLS.
//!
//! After the gateway's CONNECT preamble yields the session `token`, the SSH
//! server (see [`crate::server`]) offers warden the client's ephemeral key `Kc`
//! (whose fingerprint is the token's `cnf`) plus a fresh per-session key `Kw`.
//! warden verifies `cnf == fp(Kc)`, re-checks the login entitlement, records the
//! live session, and returns `{session_id, target_address, cert-over-Kw}`. The
//! worker then requires the requested login to be in the cert's principals
//! before accepting the SSH auth.
//!
//! This module owns ONLY the RPC round-trip; the security decision (principal
//! check, cert-over-Kw check) lives in [`crate::server::authorize`].

use anyhow::Context;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, SetupSessionRequest,
};
use jumpgate_mesh::tls::MeshClientCerts;

/// The successful outcome of [`setup_session`]: what warden returned for a
/// redeemed token.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    /// live_sessions PK / token jti — the worker's handle on this session.
    pub session_id: String,
    /// The target host:port the worker dials for the second hop.
    pub target_address: String,
    /// The OpenSSH certificate line minted over `Kw` (authorized_keys cert form).
    pub ssh_certificate: Vec<u8>,
}

/// Call warden's `SetupSession` over mesh mTLS.
///
/// `kc_pub` / `kw_pub` are OpenSSH public-key bytes. warden's `parseSSHPublicKey`
/// accepts an authorized_keys line first, then raw wire form — we send the
/// authorized_keys line (what `ssh_key::PublicKey::to_openssh` produces).
///
/// A transport/RPC failure (bad token, key mismatch, not authorized, replay,
/// unreachable warden, …) maps to `Err`; the caller MUST treat any `Err` as a
/// hard reject and NEVER accept the SSH auth on it.
pub async fn setup_session(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    token: &str,
    worker_id: &str,
    kc_pub: Vec<u8>,
    kw_pub: Vec<u8>,
) -> anyhow::Result<SetupOutcome> {
    let mesh_client_config = certs
        .client_config(warden_spiffe)
        .context("build warden mesh client config")?;
    let channel = crate::control::mesh_channel(warden_addr, mesh_client_config).await?;
    let mut client = DataplaneServiceClient::new(channel);

    let resp = client
        .setup_session(SetupSessionRequest {
            session_token: token.to_string(),
            worker_id: worker_id.to_string(),
            client_ssh_public_key: kc_pub,
            target_public_key: kw_pub,
        })
        .await
        .context("SetupSession rpc")?
        .into_inner();

    Ok(SetupOutcome {
        session_id: resp.session_id,
        target_address: resp.target_address,
        ssh_certificate: resp.ssh_certificate,
    })
}
