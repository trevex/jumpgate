# Security & threat model

The consolidated security posture of jumpgate — what it defends and how. This page
**references** the detailed treatments elsewhere ([access-model.md](access-model.md),
[architecture.md](architecture.md), [capabilities.md](capabilities.md),
[decisions.md](decisions.md)) rather than duplicating them. Where a defense applies
only to a protocol that is not yet built, it says so.

## Posture — what we defend

- **Least privilege by construction.** Access is **requestable + approval-gated +
  JIT time-boxed**: nothing is standing unless an admin binds it, and a role is
  requestable only where a **RequestPolicy** exists and the caller is *eligible* for
  it (holds a `requester_role` on the scope **via a standing binding**, or is a
  named `requester` subject). The approval gate travels with the role. The workflow
  is request → N-of-M approve (self-service at `required_approvals=0`) → a
  **time-boxed `access_grants` row** that authorizes like a standing binding until
  its `expires_at`/revoke → a reaper. Grant lifetime is clamped to
  `min(requested, policy.max_duration, MaxGrantTTL=8h)`. See
  [access-model.md](access-model.md#approval--who-signs-off-and-how-a-request-activates).
- **Grants confer access, not governance.** A role obtained via a JIT
  `access_grant` gives real access (it joins the `HoldsRole` held closure) but is
  **excluded** from the requester/approver predicates, which resolve
  **standing-only** (`HoldsRoleStanding`). A granted `requester_role`/`approver_role`
  can **never** be used to request or approve *further* access, closing
  self-escalation loops.
- **Agentless L7 gateway.** No software is installed on target hosts; the worker
  terminates the protocol and injects a short-lived credential at the edge. Live for
  SSH; other protocols are additive workers.
- **Centralized security-critical state.** The vault, policy, and grants live in
  warden (Go); a data-plane worker holds a credential only for the life of one
  authorized session.

## Existence-hiding — topology never leaks

Discoverability is itself a permission. `ListAssets`/`ListFolders` return
**only** the nodes a caller can see (Active ∪ Requestable, or manageable). A
direct lookup of an **invisible** asset returns **`CodeNotFound`, never
`CodePermissionDenied`**, so an attacker cannot map infrastructure by probing for
`403`s. Browsing an unrelated folder path also returns `CodeNotFound`. The same
NotFound-hiding applies to `Resolve*` for folders, roles, groups, and policies.
See the visibility tiers in
[access-model.md](access-model.md#requestable-eligibility--visibility-tiers--what-can-i-see--ask-for).

## AuthN & token model

Two distinct token mechanisms:

- **API bearer tokens.** Login/API authentication uses **opaque, DB-backed, hashed
  bearer tokens** — not JWTs. Passwords are hashed with **argon2id**; a successful
  login mints a random token stored **hashed** (`auth_tokens.token_hash`) with an
  expiry, presented as `Authorization: Bearer <token>`. Because the server holds the
  token record, revocation is **instant and server-side** (delete the row).
- **Session admission tokens.** The short-lived token that admits a data-plane
  session is a **separate** mechanism: a **PASETO v4.public** token (Ed25519),
  minted by `CreateSession`, bound to the client's ephemeral key fingerprint
  (`cnf`), and verified **offline** by the gateway. The signing key is DB-backed and
  sealed at rest. This is what lets the externally-exposed gateway authorize a
  connection without a round-trip to warden, while the worker still re-checks the
  binding and re-authorizes at `SetupSession`.

## Capability enforcement boundary

Capabilities are **format-validated at role creation** (protovalidate) and are
**opaque tokens** to warden. warden **decides** (resolves held roles → capability
set → yes/no via `Check`/`CapMatch`); enforcement happens in two places:

- **Management plane** — warden enforces directly in each RPC handler
  (`requireCap` at the relevant scope). This replaced the old boolean `is_admin`
  gate: there is no admin flag, only capabilities.
- **Data plane** — the worker enforces protocol semantics at a live session
  (mapping a protocol operation to a capability, checking it, and configuring the
  access). Live for **SSH** (`ssh:*`); `db:*` / `k8s:*` are defined for the model
  and land with their proxies.

See [capabilities.md](capabilities.md#where-enforcement-lives-data-plane--warden-decides-workers-enforce).

## Account deactivation

`users.deactivated_at` (NULL = active) is an **immediate off-switch** for a
principal, enforced at **three** layers:

- **Login** (`AuthService.Login`): a deactivated account **cannot mint a new
  token** — login fails with `CodeUnauthenticated`.
- **Auth interceptor**: on every authenticated RPC the resolved user is re-checked;
  if `deactivated_at` is set the load fails and the call is `CodeUnauthenticated`
  **even with an otherwise-valid, unexpired token**.
- **Authorization closures**: every authz query filters `deactivated_at IS NULL`, so
  a deactivated user **holds nothing and counts for nothing** — not in their own
  `HoldsRole` closure, and not as an approver, `requester_role`/`approver_role`
  holder, or contributor to anyone else's closure via group membership or a named
  policy subject. Deactivation **also cascades to JIT grants**: `DeactivateUser`
  revokes the user's active `access_grants` (reason `user_deactivated`), each audited
  and routed to teardown, so their live sessions are torn down.

So deactivation is a complete, reversible off-switch (reactivate with
`ReactivateUser`, or hard-`DeleteUser` with FKs cascading) — it stops the principal
from authenticating or acting **and** removes them from everyone's resolution,
without deleting their bindings, memberships, or audit history.

## Continuous enforcement — revocation tears down live sessions

Authorization is **continuous, not connect-time only**: revoking a permission
**terminates any live session that depended on it**, not just blocks the next
connect. Because the held closure filters `revoked_at IS NULL AND expires_at >
now()`, a revoked/expired grant stops conferring access immediately — and the live
session it supported is force-closed by warden signalling the owning worker.

Every revocation source below re-evaluates the affected sessions and tears down
those no longer permitted, each **audited** (`session.terminated`, alongside the
revocation event):

| Revocation source | Who / what | Authorized for |
|---|---|---|
| **Grant expiry** | the in-process **reaper** (`ReaperInterval`, 30s) sweeps grants past `expires_at`, sets `revoked_reason='expired'` | automatic (system) |
| **Manual `RevokeGrant`** | an explicit revoke of one grant | a holder of `access:grant:revoke` · the grant's **subject** (self-revoke) · **any standing approver** for its (role, asset) |
| **Deactivation** | `DeactivateUser` revokes the user's active grants | the deactivation actor |
| **Standing-authz change** | a deleted role binding, a removed group membership, a changed role-rewrite rule, or a dropped role capability | the admin who made the change |

Detection is **push + pull**: a Postgres `authz_changed` notification drives
near-instant re-evaluation, and a periodic ownership-partitioned **sweep**
(debounced) is the level-triggered backstop; an orphan GC reconciles unreachable
workers and stuck teardowns off a worker-presence heartbeat. Full treatment in
[architecture.md](architecture.md#continuous-revocation--live-session-teardown).

## Tamper-evident audit

Every security-relevant event is appended to a **hash-chained, append-only** audit
log: `entry_hash = sha256(prev_hash ‖ canonical(entry))`, so any after-the-fact edit
or deletion breaks the chain and is detectable (`Verify`).

**Durability — transactional outbox.** The audit logger's direct `Append` opens its
own advisory-locked transaction and cannot enlist in a domain transaction, so a
post-commit append would leave a crash window between the domain commit and the
append. State-changing services (the JIT request/approve/deny/cancel/grant paths,
the reaper, session setup/teardown) instead **enqueue** each event into an
`audit_outbox` row **inside the same domain transaction**: the event and the action
it records commit atomically or not at all. If the enqueue fails, the whole
transaction rolls back, so there is no silent gap. A background **drainer** moves
outbox rows into the hash-chained `audit_log` in one advisory-locked transaction —
chaining then deleting each row together, so delivery is exactly-once and re-drains
safely after a crash.

One event is deliberately **not** on the outbox: the vault's `credential.issued`
(`Broker.Issue`) is a genuinely **post-fact** append — the certificate is already
minted and returned, with no domain transaction to enlist in — so it uses direct
`Append`. Its narrow crash window is benign (a re-issue is harmless).

## Secrets at rest

The vault **envelope-encrypts** every secret it holds — CA private keys, the
session-signing key, and stored target secrets. Each secret gets a fresh random
**256-bit DEK** that encrypts the plaintext (**AES-256-GCM**); the DEK is then
**wrapped** by a **master KEK** (also AES-256-GCM). Plaintext **never** touches the
DB unsealed, and sealed bytes are **never** returned via the API — decryption
happens only inside the broker to hand a credential to a worker for a live,
authorized session. GCM makes it **fail-closed**: a wrong KEK or a tampered blob
fails `Open`. See [architecture.md](architecture.md#vault--credentialbroker).

- **Master-key custody.** The KEK is a base64 32-byte `VAULT_MASTER_KEY` (**env for
  now**; a **KMS** is the future seam — only the DEK-wrap step changes, so
  master-key rotation re-wraps DEKs without touching ciphertexts). The vault is
  **disabled** (fail-closed, warn at boot) if the key is unset, **fatal** if
  malformed.
- **⚠ Losing the master key loses all sealed secrets.** There is no recovery path —
  the DEKs are wrapped under it. Custody of `VAULT_MASTER_KEY` (or the future KMS
  key) is a top-tier operational secret.

**Short-lived, capability-scoped credentials.** The credential the broker mints is
**bounded by the granting authorization**: `SetupSession` passes the remaining
lifetime into the cert's `ValidBefore` / the secret's validity, so a credential
never outlives the access behind it. For SSH the cert's principals are
**capability-derived and host-scoped**: the broker mints only the logins the user
holds `ssh:login:<login>` for, as `<login>@<asset>` principals — **no static host
login**. An empty entitlement is refused, and the SSH CA **independently refuses to
sign a principal-less cert** (which OpenSSH would treat as valid for every account)
as defense-in-depth. Every issuance appends `credential.issued`. See
[access-model.md](access-model.md#ssh-access--os-logins-are-capabilities).

## Threat-model summary

| Threat | Mitigation | Status |
|---|---|---|
| Attacker maps infrastructure by probing | Existence-hiding: catalog returns only visible assets; invisible lookup → `CodeNotFound`, never `403` | Implemented |
| Stolen/leaked bearer token used indefinitely | Opaque DB-backed hashed tokens with expiry; instant server-side revocation | Implemented |
| Privilege creep / broad standing access | Requestable + approval-gated + JIT time-boxed grants (clamped to `MaxGrantTTL=8h`); approval gate travels with the role | Implemented |
| JIT grant used to self-escalate (approve/request more) | Grants confer access but **not governance**: requester/approver predicates are standing-only, excluding active grants | Implemented |
| Over-broad management authority delegated | No-escalation subset rule: you can only bind/grant a role whose capabilities you already hold at that scope (`Covers`) | Implemented |
| Over-broad capability grant slips in unnoticed | Grammar validation at role creation; `**` is the explicit, auditable "whole scope"; `CapMatch` fails closed | Implemented |
| Access revoked but live session continues | Grant/binding/membership/capability change re-evaluates authz and **force-closes** dependent live sessions (push + pull, audited) | Implemented (SSH) |
| Compromised/departed user keeps acting | `deactivated_at` off-switch: rejected at Login **and** the auth interceptor, **and** filtered out of every authz closure; active grants revoked and sessions torn down | Implemented |
| Credential exposed on a compromised target | Agentless: no credential/software on targets; the credential is **short-lived** (bounded by the grant) and the worker holds it only for a live session | Implemented (SSH) |
| Over-broad SSH host login (static account, root-for-all) | SSH cert principals are **capability-derived and host-scoped**: only logins the user holds `ssh:login:<login>` for, bound to the asset; empty → refused; the CA refuses a principal-less cert | Implemented |
| Session activity not attributable / disputable | SSH sessions recorded by default (asciicast v2) at the worker, fail-closed, streamed to object storage with a rolling SHA-256; admin retrieval is presigned and audited | Implemented (SSH) |
| Audit log tampered to hide activity | Hash-chained append-only log, independently verifiable; events enqueued in-tx via a transactional outbox (crash window closed; `credential.issued` post-fact) | Implemented |
| Secrets (CA keys, target creds) read at rest | Envelope encryption: per-secret AES-256-GCM DEK wrapped by a master KEK (`VAULT_MASTER_KEY`; KMS-pluggable); sealed bytes never leave the DB/API; fail-closed `Open` | Implemented |
| Master key lost/leaked | Losing `VAULT_MASTER_KEY` loses all sealed secrets (no recovery); KMS custody is the future seam — treat the key as a top-tier operational secret | Residual (documented; KMS deferred) |
| Worker impersonates another identity | mesh mTLS: warden derives the authoritative `worker_id` from the peer cert's SPIFFE SAN; the gateway pins each peer's SPIFFE id (chain-to-mesh-CA **and** URI-SAN match) | Implemented |

## Related

- [access-model.md](access-model.md) — who can do what, and the visibility tiers.
- [capabilities.md](capabilities.md) — the capability vocabulary and the
  decide/enforce split.
- [architecture.md](architecture.md) — the data plane, continuous revocation, audit.
- [data-model.md](data-model.md) — the tables behind all of the above.
- [decisions.md](decisions.md) — rationale for the auth, audit, and data-plane
  choices.
