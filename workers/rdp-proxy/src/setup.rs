//! The worker's two-stage session setup client over mesh mTLS.
//!
//! 1. [`prepare_session`] — redeem the session token, record the live session, and
//!    learn the endpoint + the asset's active TLS trust anchors, WITHOUT any
//!    credential. warden re-checks the `rdp:login:<login>` entitlement here.
//! 2. the bridge observes the target's TLS identity and matches it against those
//!    anchors (credential-free), then
//! 3. [`issue_session_credential`] — ONLY after a match, the worker asks warden to
//!    release the target password (warden re-verifies the observation before
//!    releasing). The password is injected into the Client Info PDU worker-side; it
//!    never reaches the browser.
//!
//! The browser has no client key of its own (the mesh mTLS tunnel is already
//! authenticated), so both calls send an EMPTY `client_ssh_public_key` /
//! `target_public_key` — warden's `mode=web` token skips the `cnf` proof and takes
//! the login from the ticket, exactly as the ssh-proxy browser-terminal ingress does.

use anyhow::{anyhow, Context};
use zeroize::Zeroizing;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, issue_session_credential_response,
    IssueSessionCredentialRequest, PrepareSessionRequest,
};
use jumpgate_mesh::tls::MeshClientCerts;

use crate::probe::SessionAnchor;

/// The credential-free outcome of [`prepare_session`]: the endpoint, its current
/// revision, and the asset's active trust anchors. NEVER carries a credential.
#[derive(Debug, Clone)]
pub struct PrepareOutcome {
    /// live_sessions PK / token jti — the worker's handle on this session.
    pub session_id: String,
    /// The asset's endpoint revision at prepare time. Echoed to `IssueCredential`
    /// so warden can reject a match against a moved endpoint.
    pub endpoint_revision: i64,
    /// The target host:port the worker dials for the RDP hop.
    pub target_address: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Carried through for session attribution.
    pub grant_id: String,
    /// Whether warden requires this session to be recorded (else refuse it).
    pub recording_required: bool,
    /// The object key warden assigned for this session's recording.
    pub recording_object_key: String,
    /// The login/role warden authorized (authoritative for the target hop).
    pub login: String,
    /// The asset's current active trust anchors to match the observed target
    /// identity against. An empty set means nothing to match → fail closed.
    pub anchors: Vec<SessionAnchor>,
}

/// Call warden's `PrepareSession` over mesh mTLS.
///
/// Any transport/RPC failure (bad token, not authorized, replay, unreachable
/// warden, identity unverified, …) maps to `Err`; the caller MUST treat any `Err`
/// as a hard reject and NEVER bridge the session on it.
pub async fn prepare_session(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    token: &str,
    worker_id: &str,
    login: &str,
) -> anyhow::Result<PrepareOutcome> {
    let mesh_client_config = certs
        .client_config(warden_spiffe)
        .context("build warden mesh client config")?;
    let channel = jumpgate_mesh::channel::mesh_channel(warden_addr, mesh_client_config).await?;
    let mut client = DataplaneServiceClient::new(channel);

    let resp = client
        .prepare_session(PrepareSessionRequest {
            session_token: token.to_string(),
            worker_id: worker_id.to_string(),
            // The browser offers no client key; warden's web token skips the cnf
            // proof and takes the login from the ticket.
            client_ssh_public_key: Vec::new(),
            login: login.to_string(),
        })
        .await
        .context("PrepareSession rpc")?
        .into_inner();

    let anchors = resp
        .trust_anchors
        .into_iter()
        .map(|a| SessionAnchor {
            id: a.id,
            kind: a.kind,
            fingerprint: a.sha256_fingerprint,
            required_dns_names: a.required_dns_names,
            required_ip_addresses: a.required_ip_addresses,
            public_material: a.public_material,
        })
        .collect();

    Ok(PrepareOutcome {
        session_id: resp.session_id,
        endpoint_revision: resp.endpoint_revision,
        target_address: resp.target_address,
        grant_id: resp.grant_id,
        recording_required: resp.recording_required,
        recording_object_key: resp.recording_object_key,
        login: resp.login,
        anchors,
    })
}

/// Call warden's `IssueSessionCredential` over mesh mTLS: release the target
/// password for a prepared session AFTER the worker matched the observed target
/// identity against `matched_anchor_id`. warden re-verifies the observation before
/// releasing; a verification failure maps to `Err` (no credential).
///
/// An RDP asset login is always password-backed, so only the generic `password`
/// arm is accepted; every other arm is a hard error (a control-plane bug we refuse
/// rather than misuse). The returned password is held in [`Zeroizing`].
#[allow(clippy::too_many_arguments)]
pub async fn issue_session_credential(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    session_id: &str,
    worker_id: &str,
    endpoint_revision: i64,
    matched_anchor_id: &str,
    observed_fingerprint: &str,
) -> anyhow::Result<Zeroizing<String>> {
    let mesh_client_config = certs
        .client_config(warden_spiffe)
        .context("build warden mesh client config")?;
    let channel = jumpgate_mesh::channel::mesh_channel(warden_addr, mesh_client_config).await?;
    let mut client = DataplaneServiceClient::new(channel);

    let resp = client
        .issue_session_credential(IssueSessionCredentialRequest {
            session_id: session_id.to_string(),
            worker_id: worker_id.to_string(),
            endpoint_revision,
            matched_anchor_id: matched_anchor_id.to_string(),
            observed_fingerprint: observed_fingerprint.to_string(),
            target_public_key: Vec::new(),
        })
        .await
        .context("IssueSessionCredential rpc")?
        .into_inner();

    match resp.credential {
        Some(issue_session_credential_response::Credential::Password(pw)) => {
            Ok(Zeroizing::new(pw))
        }
        Some(issue_session_credential_response::Credential::SshCertificate(_))
        | Some(issue_session_credential_response::Credential::PrivateKey(_))
        | Some(issue_session_credential_response::Credential::X509Certificate(_))
        | Some(issue_session_credential_response::Credential::PgPassword(_)) => {
            Err(anyhow!("unexpected non-password credential on an rdp worker"))
        }
        None => Err(anyhow!("IssueSessionCredential returned no credential")),
    }
}
