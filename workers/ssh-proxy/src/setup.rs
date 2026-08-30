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

use anyhow::anyhow;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, setup_session_response, SetupSessionRequest,
};
use jumpgate_mesh::tls::MeshClientCerts;

/// The credential warden returned for a redeemed session — a discriminated
/// union mirroring the dataplane `SetupSessionResponse.credential` oneof.
///
/// Which variant is returned is driven by the asset login's configured `kind`:
/// - `Cert` (kind `ca`): an OpenSSH certificate line minted over `Kw`; the
///   worker presents it with `Kw` on the target hop.
/// - `Password` (kind `password`): a plain stored password, injected as the
///   target's password auth.
/// - `Key` (kind `key`): a plain stored OpenSSH private-key PEM, injected as the
///   target's publickey auth.
///
/// The secret variants (`Password`/`Key`) never touch the client — they are used
/// solely worker-side to authenticate the second hop.
#[derive(Debug, Clone)]
pub enum TargetCredential {
    /// OpenSSH certificate line (authorized_keys cert form), minted over `Kw`.
    Cert(Vec<u8>),
    /// Plain stored password.
    Password(String),
    /// Plain stored OpenSSH private-key PEM.
    Key(Vec<u8>),
}

/// The successful outcome of [`setup_session`]: what warden returned for a
/// redeemed token.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    /// live_sessions PK / token jti — the worker's handle on this session.
    pub session_id: String,
    /// The target host:port the worker dials for the second hop.
    pub target_address: String,
    /// The asset's configured target host-key pin (an OpenSSH authorized_keys
    /// line), or empty for no pin. When non-empty the worker rejects a target
    /// whose presented host key does not match (fail closed / MITM protection).
    pub target_host_key: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Carried through to the recording report for session attribution.
    pub grant_id: String,
    /// The credential the worker uses to authenticate to the target as the login.
    pub credential: TargetCredential,
    /// Whether warden requires this session to be recorded (else refuse it).
    pub recording_required: bool,
    /// The object key warden assigned for this session's recording.
    pub recording_object_key: String,
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
#[allow(clippy::too_many_arguments)]
pub async fn setup_session(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    token: &str,
    worker_id: &str,
    login: &str,
    kc_pub: Vec<u8>,
    kw_pub: Vec<u8>,
) -> anyhow::Result<SetupOutcome> {
    let mesh_client_config = certs
        .client_config(warden_spiffe)
        .context("build warden mesh client config")?;
    let channel = jumpgate_mesh::channel::mesh_channel(warden_addr, mesh_client_config).await?;
    let mut client = DataplaneServiceClient::new(channel);

    let resp = client
        .setup_session(SetupSessionRequest {
            session_token: token.to_string(),
            worker_id: worker_id.to_string(),
            login: login.to_string(),
            client_ssh_public_key: kc_pub,
            // The worker still generates and offers Kw for the ca path; warden
            // ignores it for password/key logins.
            target_public_key: kw_pub,
        })
        .await
        .context("SetupSession rpc")?
        .into_inner();

    // A missing or unrecognized credential is a hard error: the worker must
    // never proceed without knowing how to authenticate the target hop.
    let credential = match resp.credential {
        Some(setup_session_response::Credential::SshCertificate(cert)) => {
            TargetCredential::Cert(cert)
        }
        Some(setup_session_response::Credential::Password(pw)) => TargetCredential::Password(pw),
        Some(setup_session_response::Credential::PrivateKey(key)) => TargetCredential::Key(key),
        // Postgres credential arms of the shared dataplane oneof: the gateway routes
        // by protocol so an ssh worker never receives these, but the match must be
        // exhaustive over the shared enum.
        Some(setup_session_response::Credential::X509Certificate(_))
        | Some(setup_session_response::Credential::PgPassword(_)) => {
            return Err(anyhow!("unexpected postgres credential on an ssh worker"));
        }
        None => return Err(anyhow!("SetupSession returned no credential")),
    };

    Ok(SetupOutcome {
        session_id: resp.session_id,
        target_address: resp.target_address,
        target_host_key: resp.target_host_key,
        grant_id: resp.grant_id.clone(),
        credential,
        recording_required: resp.recording_required,
        recording_object_key: resp.recording_object_key,
    })
}
