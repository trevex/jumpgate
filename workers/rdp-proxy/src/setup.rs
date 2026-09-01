//! The worker's SetupSession client: redeem a session token against warden over
//! mesh mTLS.
//!
//! The browser has no client key of its own (the mesh mTLS tunnel is already
//! authenticated), so this sends an EMPTY `client_ssh_public_key` and an empty
//! `target_public_key` — warden's `mode=web` token skips the `cnf` proof and
//! takes the login from the ticket, exactly as the ssh-proxy browser-terminal
//! ingress does. warden re-checks the `rdp:login:<login>` entitlement, records
//! the live session, and returns the target address + the injected password.

use anyhow::{anyhow, Context};
use zeroize::Zeroizing;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, setup_session_response, SetupSessionRequest,
};
use jumpgate_mesh::tls::MeshClientCerts;

/// The credential warden returned for a redeemed RDP session. An RDP asset login
/// is always password-backed (the vault secret is injected into the Client Info
/// PDU inside TLS, worker-side — it never reaches the browser). Held in
/// [`Zeroizing`] so the bytes are scrubbed on drop; [`Debug`] redacts it.
#[derive(Clone)]
pub enum TargetCredential {
    /// Plain stored password.
    Password(Zeroizing<String>),
}

impl std::fmt::Debug for TargetCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => write!(f, "Password(<redacted>)"),
        }
    }
}

/// The successful outcome of [`setup_session`]: what warden returned for a
/// redeemed token.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    /// live_sessions PK / token jti — the worker's handle on this session.
    pub session_id: String,
    /// The target host:port the worker dials for the RDP hop.
    pub target_address: String,
    /// The asset's configured target-server CA (PEM). When non-empty the worker
    /// verifies the target's TLS server cert against it (fail closed / MITM
    /// protection); empty = accept any (TOFU-off, used for the xrdp bring-up).
    pub target_server_ca: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Carried through for session attribution.
    pub grant_id: String,
    /// The credential the worker uses to authenticate to the target as the login.
    pub credential: TargetCredential,
    /// Whether warden requires this session to be recorded (Phase 2 never does).
    pub recording_required: bool,
    /// The object key warden assigned for this session's recording.
    pub recording_object_key: String,
}

/// Call warden's `SetupSession` over mesh mTLS.
///
/// Any transport/RPC failure (bad token, not authorized, replay, unreachable
/// warden, …) maps to `Err`; the caller MUST treat any `Err` as a hard reject and
/// NEVER bridge the session on it.
pub async fn setup_session(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    token: &str,
    worker_id: &str,
    login: &str,
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
            // The browser offers no client key; warden's web token skips the cnf
            // proof and takes the login from the ticket.
            client_ssh_public_key: Vec::new(),
            target_public_key: Vec::new(),
        })
        .await
        .context("SetupSession rpc")?
        .into_inner();

    // An RDP worker accepts ONLY the generic `password` arm. Every other arm is a
    // hard error — the gateway routes by protocol, so a non-password credential on
    // an rdp worker is a control-plane bug we refuse rather than misuse.
    let credential = match resp.credential {
        Some(setup_session_response::Credential::Password(pw)) => {
            TargetCredential::Password(Zeroizing::new(pw))
        }
        Some(setup_session_response::Credential::SshCertificate(_))
        | Some(setup_session_response::Credential::PrivateKey(_))
        | Some(setup_session_response::Credential::X509Certificate(_))
        | Some(setup_session_response::Credential::PgPassword(_)) => {
            return Err(anyhow!("unexpected non-password credential on an rdp worker"));
        }
        None => return Err(anyhow!("SetupSession returned no credential")),
    };

    Ok(SetupOutcome {
        session_id: resp.session_id,
        target_address: resp.target_address,
        target_server_ca: resp.target_server_ca,
        grant_id: resp.grant_id,
        credential,
        recording_required: resp.recording_required,
        recording_object_key: resp.recording_object_key,
    })
}
