//! The worker's two-phase session client: redeem a session token against warden
//! over mesh mTLS, in the enforced verify-before-issue order.
//!
//! After the gateway's CONNECT preamble yields the session `token`, the SSH
//! server (see [`crate::server`]) runs the two-phase flow:
//!
//! 1. [`prepare_session`] — offer warden the client's ephemeral key `Kc` (whose
//!    fingerprint is the token's `cnf`) and the requested login. warden verifies
//!    `cnf == fp(Kc)`, re-checks the login entitlement, records the live session,
//!    and returns the endpoint + the asset's current **trust anchors** — but NO
//!    credential.
//! 2. The worker connects to the target, observes its host key, and matches the
//!    observation against an approved anchor (see [`crate::server`]).
//! 3. [`issue_session_credential`] — ONLY after a match, the worker asks warden to
//!    release the target credential (minted over the per-session key `Kw`). warden
//!    re-verifies the observed identity against a current active anchor before
//!    minting (defence in depth).
//!
//! This module owns ONLY the RPC round-trips; the identity match and the
//! credential checks (cert-over-`Kw`, host-scoped principals) live in
//! [`crate::server`].

use anyhow::{anyhow, Context};
use zeroize::Zeroizing;

use jumpgate_mesh::pb::jumpgate::dataplane::v1::{
    dataplane_service_client::DataplaneServiceClient, issue_session_credential_response,
    IssueSessionCredentialRequest, PrepareSessionRequest,
};
use jumpgate_mesh::tls::MeshClientCerts;

/// The credential warden released for a verified session — a discriminated union
/// mirroring the dataplane `IssueSessionCredentialResponse.credential` oneof.
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
/// solely worker-side to authenticate the second hop. They are held in
/// [`Zeroizing`] so the bytes are scrubbed on drop, and [`Debug`] is hand-written
/// to redact them (a stray `?credential` in a log must never print a secret).
#[derive(Clone)]
pub enum TargetCredential {
    /// OpenSSH certificate line (authorized_keys cert form), minted over `Kw`.
    /// Not secret (a public certificate), so it is not zeroized.
    Cert(Vec<u8>),
    /// Plain stored password.
    Password(Zeroizing<String>),
    /// Plain stored OpenSSH private-key PEM.
    Key(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for TargetCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cert(_) => write!(f, "Cert(<cert>)"),
            Self::Password(_) => write!(f, "Password(<redacted>)"),
            Self::Key(_) => write!(f, "Key(<redacted>)"),
        }
    }
}

/// A public trust anchor warden returned at prepare time: the identity constraint
/// the worker must satisfy before a credential is released. Public material only —
/// no secret, no credential.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// warden's anchor id (echoed back as `matched_anchor_id` on a match).
    pub id: String,
    /// `ssh_host_key` | `ssh_host_ca` | `tls_leaf` | `tls_ca`. Only `ssh_host_key`
    /// is verifiable at SSH session time (see [`crate::server`]); the others fail
    /// closed.
    pub kind: String,
    /// Host-key algorithm, OpenSSH form (e.g. `ssh-ed25519`).
    pub algorithm: String,
    /// `SHA256:...` fingerprint of the approved host key/identity.
    pub sha256_fingerprint: String,
}

/// The credential-free outcome of [`prepare_session`]: the endpoint, the current
/// endpoint revision, and the active trust anchors. NEVER carries a credential.
#[derive(Debug, Clone)]
pub struct PrepareOutcome {
    /// live_sessions PK / token jti — the worker's handle on this session.
    pub session_id: String,
    /// The asset's endpoint revision at prepare time. Echoed to `IssueCredential`
    /// so warden can reject a match against a moved endpoint.
    pub endpoint_revision: i64,
    /// The target host:port the worker dials for the second hop.
    pub target_address: String,
    /// The access grant that authorized this session (empty for standing-only
    /// access). Carried through to the recording report for session attribution.
    pub grant_id: String,
    /// Whether warden requires this session to be recorded (else refuse it).
    pub recording_required: bool,
    /// The object key warden assigned for this session's recording.
    pub recording_object_key: String,
    /// The login/role warden authorized (authoritative for the target hop).
    pub login: String,
    /// The asset's current active trust anchors to match the observed target
    /// identity against. An empty set means nothing to match → fail closed.
    pub anchors: Vec<TrustAnchor>,
}

/// The credential-bearing outcome of [`issue_session_credential`].
#[derive(Debug)]
pub struct IssueOutcome {
    /// The credential the worker uses to authenticate to the target as the login.
    pub credential: TargetCredential,
}

/// Call warden's `PrepareSession` over mesh mTLS: redeem the token, record the
/// live session, and learn the endpoint + trust anchors WITHOUT a credential.
///
/// `kc_pub` is the client's ephemeral OpenSSH public-key bytes (authorized_keys
/// line), or empty for the browser terminal's web-mode token.
///
/// A transport/RPC failure (bad token, key mismatch, not authorized, replay,
/// unreachable warden, …) maps to `Err`; the caller MUST treat any `Err` as a
/// hard reject and NEVER accept the SSH auth on it.
pub async fn prepare_session(
    warden_addr: &str,
    warden_spiffe: &str,
    certs: &MeshClientCerts,
    token: &str,
    worker_id: &str,
    login: &str,
    kc_pub: Vec<u8>,
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
            client_ssh_public_key: kc_pub,
            login: login.to_string(),
        })
        .await
        .context("PrepareSession rpc")?
        .into_inner();

    let anchors = resp
        .trust_anchors
        .into_iter()
        .map(|a| TrustAnchor {
            id: a.id,
            kind: a.kind,
            algorithm: a.algorithm,
            sha256_fingerprint: a.sha256_fingerprint,
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
/// credential for a prepared session AFTER the worker matched the observed target
/// identity against `matched_anchor_id`. warden re-verifies the observation before
/// minting; a verification failure maps to `Err` (no credential).
///
/// `kw_pub` is the per-session OpenSSH public-key bytes the ca path certifies
/// (empty for password/key logins).
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
    kw_pub: Vec<u8>,
) -> anyhow::Result<IssueOutcome> {
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
            target_public_key: kw_pub,
        })
        .await
        .context("IssueSessionCredential rpc")?
        .into_inner();

    // A missing or unrecognized credential is a hard error: the worker must never
    // proceed without knowing how to authenticate the target hop.
    let credential = match resp.credential {
        Some(issue_session_credential_response::Credential::SshCertificate(cert)) => {
            TargetCredential::Cert(cert)
        }
        Some(issue_session_credential_response::Credential::Password(pw)) => {
            TargetCredential::Password(Zeroizing::new(pw))
        }
        Some(issue_session_credential_response::Credential::PrivateKey(key)) => {
            TargetCredential::Key(Zeroizing::new(key))
        }
        // Postgres credential arms of the shared dataplane oneof: the gateway routes
        // by protocol so an ssh worker never receives these, but the match must be
        // exhaustive over the shared enum.
        Some(issue_session_credential_response::Credential::X509Certificate(_))
        | Some(issue_session_credential_response::Credential::PgPassword(_)) => {
            return Err(anyhow!("unexpected postgres credential on an ssh worker"));
        }
        None => return Err(anyhow!("IssueSessionCredential returned no credential")),
    };

    Ok(IssueOutcome { credential })
}
