# Security & threat model

The consolidated security posture of jumpgate — what it defends, how, and which
mechanisms are implemented versus planned. This page **references** the detailed
treatments elsewhere ([access-model.md](access-model.md),
[architecture.md](architecture.md), [capabilities.md](capabilities.md),
[decisions.md](decisions.md)) rather than duplicating them.

> **Status:** most control-plane mechanisms are implemented today
> (existence-hiding, the opaque-token auth model, capability validation, the audit
> primitive, the full **JIT request→approve→grant→reaper** workflow with
> time-boxed least-privilege grants and their revocation matrix (M3c), and
> **secrets-at-rest** — the envelope-encrypting **CredentialBroker/vault** (M3d,
> which **completes M3**)); the **data-plane** enforcement, live-session
> **teardown**, and live credential **injection** are still **planned** (M4/M5).
> Each item below is marked.

## Posture — what we defend

- **Least privilege by construction.** Access is **requestable + approval-gated +
  JIT time-boxed**: nothing is standing unless an admin binds it, and a role is
  requestable only where a **RequestPolicy** exists and the caller is *eligible*
  for it (holds a `requester_role` on the scope **via a standing binding**, or is a
  named `requester` subject) — the approval gate travels with the role
  (see [access-model.md](access-model.md#approval--who-signs-off-and-how-a-request-activates-m3c-workflow)).
  ✅ The full workflow is built (M3c): request→N-of-M approve (self-service at
  `required_approvals=0`)→a **time-boxed `access_grants` row** that authorizes like
  a standing binding until its `expires_at`/revoke→reaper. Grant lifetime is clamped
  to `min(requested, policy.max_duration, MaxGrantTTL=8h)`. (Request-policy
  resolution + eligibility/approver predicates landed in M3b + Access-Model v2.)
- **Grants confer access, not governance.** A role obtained via a JIT
  `access_grant` gives real access (it joins the `HoldsRole` held closure) but is
  **excluded** from the requester/approver predicates, which resolve **standing-only**
  (`HoldsRoleStanding`). So a granted `requester_role`/`approver_role` can **never**
  be used to request or approve *further* access — this closes self-escalation loops
  where a JIT grant would otherwise bootstrap more privilege. ✅ (M3c)
- **Agentless L7 gateway.** No software is installed on target hosts; the proxy
  terminates the protocol and injects credentials at the edge
  ([decisions.md](decisions.md)). ⬜ Data plane planned (M4/M5).
- **Centralized security-critical state ("Approach A").** The vault, policy, and
  grants live in warden (Go); the data plane holds a credential only for the life
  of an authorized session
  ([architecture.md](architecture.md#data-plane-interaction-model-approach-a)).
  ✅ The **vault** — envelope-encrypted secrets + the CAs + the `CredentialBroker`
  seam — is built (M3d); the data-plane worker that receives a minted credential is
  M4.

## Existence-hiding — topology never leaks

Discoverability is itself a permission. The catalog (`ListVisibleAssets`) returns
**only** the assets a caller can see (Active ∪ Requestable). A direct lookup of an
**invisible** asset returns **`CodeNotFound`, never `CodePermissionDenied`** — so
an attacker cannot map infrastructure by probing for `403`s. See the visibility
tiers in [access-model.md](access-model.md#requestable-eligibility--visibility-tiers--what-can-i-see--ask-for).
**Implemented** (M2).

## AuthN & token model

Login/API authentication uses **opaque, DB-backed, hashed bearer tokens** — not
JWTs. Passwords are hashed with **argon2id**; a successful login mints a random
token stored **hashed** (`auth_tokens.token_hash`) with an expiry, presented as
`Authorization: Bearer <token>`. Because the server holds the token record,
revocation is **instant and server-side** (delete the row) — no waiting for a
signed token to expire. **Implemented** (M2b).

> Note: the short-lived **session** tokens that bind a data-plane session to a
> grant are a **separate** mechanism (PASETO v4, planned with the token minter /
> M4) — see [decisions.md](decisions.md) and
> [architecture.md](architecture.md).

## Account deactivation

`users.deactivated_at` (NULL = active) is an **immediate off-switch** for a
principal, enforced at **two** points:

- **Login** (`AuthService.Login`): a deactivated account **cannot mint a new
  token** — login fails with `CodeUnauthenticated`.
- **Auth interceptor** (`Lookup.Load`): on every authenticated RPC the resolved
  user is re-checked; if `deactivated_at` is set the load fails, the interceptor
  leaves no user on the context, and the call fails with `CodeUnauthenticated`
  **even with an otherwise-valid, unexpired token**.

So deactivation stops the principal from **authenticating or acting**, without
deleting their bindings, memberships, or audit history (they can be reactivated
with `ReactivateUser`; the account can also be hard-`DeleteUser`d, FKs cascading).
Deactivation also **cascades to JIT grants**: `DeactivateUser` revokes the user's
active `access_grants` (reason `user_deactivated`), each audited and routed to the
teardown seam (M3c). It is one of the
[continuous-revocation](#continuous-enforcement--revocation-tears-down-live-sessions)
triggers that will, once the M4 gateway kill path lands, also terminate the user's
live sessions.

> **Residual limitation (explicit).** Deactivation blocks the deactivated user's
> **own** actions, but the user **still counts in *other* users' authz sets**: they
> remain a valid **approver** / `requester_role`- or `approver_role`-holder and
> still contribute to others' `HoldsRole` closure via group membership or as a
> named policy subject — until their `role_bindings`/memberships are removed or the
> account is deleted. **Full exclusion** — a `deactivated_at IS NULL` filter inside
> the `HoldsRole` / requestable / approver CTEs so a deactivated user vanishes from
> everyone's resolution — is **deferred** (a follow-up). Today, revoke access by
> removing the binding/membership (or deleting the account), not by deactivation
> alone. **Implemented** (deactivation off-switch, M-v2); full authz-set exclusion
> **planned**.

**Implemented** (Access-Model v2).

## Capability enforcement boundary

Capabilities are **format-validated at role creation** (protovalidate) and are
**opaque tokens** to warden: warden **decides** (resolves held roles → capability
set → yes/no via `Check`/`CapMatch`), the **workers enforce** (map a protocol
operation → a capability, check it, and configure the access). See
[capabilities.md](capabilities.md#where-enforcement-lives--warden-decides-workers-enforce).
Validation + decision **implemented**; enforcement **planned** (M4/M5).

## Continuous enforcement — revocation tears down live sessions

Authorization is **continuous, not connect-time only**: revoking a permission
must terminate any live session that depended on it, not just block the next
connect. Because the held closure filters `revoked_at IS NULL AND expires_at >
now()`, a revoked/expired grant **stops conferring access immediately** — but a
*live session* it supported must also be **killed**, not merely blocked at the next
connect.

For a **JIT grant** every revocation source is built (M3c), each **auditing** the
event and calling the **`GrantTerminator` teardown seam**:

| Revocation source | Who / what | Authorized for |
|---|---|---|
| **Expiry** | the in-process **reaper** (`ReaperInterval`, 30s) sweeps grants past `expires_at`, sets `revoked_reason='expired'`, actor = system | automatic |
| **Manual `RevokeGrant`** | an explicit revoke of one grant | **admin** · the grant's **subject** (self-revoke) · **any standing approver** for its (role, asset) — symmetric with approval authority |
| **Deactivation** | `DeactivateUser` cascades, revoking the user's active grants (`revoked_reason='user_deactivated'`) | admin (the deactivation actor) |

The teardown seam is a **no-op today**; the real gateway/worker session-kill path
(and the broader eligibility-change cascade for standing bindings, memberships, and
rewrite rules) is **M4** — full treatment in
[architecture.md](architecture.md#continuous-revocation--live-session-teardown-m3c-reaper--m4-gateway).
**JIT-grant revocation + audit + teardown seam: implemented (M3c). Live-session
kill: planned (M4).**

## Tamper-evident audit

Every security-relevant event is appended to a **hash-chained, append-only**
audit log: `entry_hash = sha256(prev_hash ‖ canonical(entry))`, so any
after-the-fact edit or deletion breaks the chain and is detectable
(`Verify`). The JIT workflow is fully wired (M3c): `access_request.created`/
`.approved`/`.denied`/`.cancelled` and `access_grant.activated`/`.revoked`/
`.expired`. Forced session terminations will be audited alongside the revocation
that caused them (with the M4 teardown path). The append/verify **primitive is
implemented** (M3a); wiring it across the remaining events (session start/stop,
teardown) lands with those subsystems. See
[architecture.md](architecture.md#audit--recording).

> **Audit durability — transactional outbox ✅.** The audit logger's direct
> `Append` opens its **own advisory-locked transaction** and cannot enlist in a
> domain transaction, so a post-commit append would leave a **crash window**
> between the domain commit and the append. The JIT access-request services
> (`RequestAccess`/`Approve`/`Deny`/`Cancel`/grant mint) and the expiry reaper
> instead **enqueue** each event into an `audit_outbox` row **inside the same
> domain transaction** (`Enqueue(ctx, q, …)`): the event and the action it records
> commit atomically or not at all, so a crash can never leave a durable action
> without its audit event. If the enqueue fails, the whole domain transaction
> rolls back (the action does not happen), so there is no silent gap. A background
> **drainer** (`RunDrainer`/`DrainOnce`) moves outbox rows into the hash-chained
> `audit_log` in one advisory-locked transaction — chaining then deleting each row
> together, so delivery is exactly-once and re-drains safely after a crash.
>
> One event is **not** yet on the outbox: the vault's `credential.issued`
> (`Broker.Issue`) is a genuinely **post-fact** append — the certificate is already
> minted and returned, with no domain transaction to enlist in — so it still uses
> direct `Append`. Its narrow crash window is benign (a re-issue is harmless) and
> a follow-up may fold it in.

## Secrets at rest — envelope encryption ✅ (M3d)

The **CredentialBroker** (the vault) **envelope-encrypts** every secret it holds —
CA private keys (`ca_keys.sealed`) and stored target secrets (`asset_secrets.
sealed`). Each secret gets a fresh random **256-bit DEK** that encrypts the
plaintext (**AES-256-GCM**); the DEK is then **wrapped** by a **master KEK**
(also AES-256-GCM). Plaintext **never** touches the DB unsealed, and the sealed
bytes are **never** returned via the API — decryption happens only inside the
broker to hand a credential out (in M4, to a worker for a live, authorized
session). GCM makes it **fail-closed**: a wrong KEK or a tampered blob fails
`Open`. See [architecture.md](architecture.md#vault--credentialbroker-m3d).

- **Master-key custody.** The KEK is a base64 32-byte `VAULT_MASTER_KEY`
  (**env for now**; a **KMS** is the future seam — only the DEK-wrap step changes,
  so master-key rotation re-wraps DEKs without touching ciphertexts). The vault is
  **disabled** (fail-closed, warn at boot) if the key is unset, **fatal** if
  malformed.
- **⚠ Losing the master key loses all sealed secrets.** There is no recovery path —
  the DEKs are wrapped under it. Custody of `VAULT_MASTER_KEY` (or the future KMS
  key) is a top-tier operational secret.

**Short-lived, capability-scoped credentials.** The credential the broker mints is
**bounded by the grant TTL** — the caller passes `ValidUntil` (in M4, the granting
`access_grant`'s remaining lifetime) into the cert's `ValidBefore` / the leaf's
`NotAfter`, so a credential never outlives the authorization behind it. For SSH,
the cert's principals are **capability-derived and entitlement-scoped**: the broker
intersects the host's `allowed_logins` with the user's `ssh:login:*` capabilities
(`Check`) and signs a cert whose `ValidPrincipals` is **exactly** that intersection
— **no static host login**, and `ssh:login:*` is bounded by the host allowlist. An
empty intersection is refused, and the CA **independently refuses to sign a
principal-less cert** (which OpenSSH treats as "valid for every account, incl.
root") as defense-in-depth. Every issuance appends a **`credential.issued`** audit
event. See [access-model.md](access-model.md#ssh-access--os-logins-are-capabilities-m3d).

**Implemented** (M3d — envelope crypto, both CAs, the broker + SSH/stored-secret
providers, `VaultService`). Live credential **injection** into a session is **M4**.

## Threat-model summary

| Threat | Mitigation | Status |
|---|---|---|
| Attacker maps infrastructure by probing | Existence-hiding: catalog returns only visible assets; invisible lookup → `CodeNotFound`, never `403` | Implemented (M2) |
| Stolen/leaked bearer token used indefinitely | Opaque DB-backed hashed tokens with expiry; instant server-side revocation | Implemented (M2b) |
| Privilege creep / broad standing access | Requestable + approval-gated + JIT time-boxed grants (clamped to `MaxGrantTTL`); approval gate travels with the role | Policy: M3b ✅ · request→grant→reaper workflow: M3c ✅ |
| JIT grant used to self-escalate (approve/request more) | Grants confer access but **not governance**: requester/approver predicates are standing-only (`HoldsRoleStanding`), excluding active grants | Implemented (M3c) |
| Over-broad capability grant slips in unnoticed | Grammar validation at role creation; `**` is the explicit, auditable "whole scope"; `CapMatch` fails closed | Implemented (this branch) |
| Access revoked but live session continues | Grant revoke/expiry re-evaluates authz immediately (drops from the held closure) + calls the teardown seam; forced session kill is the M4 gateway path | Grant revoke/expiry/audit/seam: M3c ✅ · live-session kill: M4 ⬜ |
| Compromised/departed user keeps acting | `deactivated_at` off-switch: rejected at Login **and** the auth interceptor (`Unauthenticated`) on any authenticated RPC | Implemented (M-v2); residual: still counts in others' authz sets until unbound/deleted (full CTE exclusion deferred) |
| Credential exposed on a compromised target | Agentless: no credential/software on targets; the credential is **short-lived** (broker-bounded by the grant TTL) and the worker holds it only for a live session | Broker + short-lived creds: M3d ✅ · agentless injection into a live session: M4 ⬜ |
| Over-broad SSH host login (static account, root-for-all) | SSH cert principals are **capability-derived**: `allowed_logins ∩ user's ssh:login:* caps`; empty → refused; the CA refuses a principal-less (all-accounts) cert | Implemented (M3d) |
| Audit log tampered to hide activity | Hash-chained append-only log; independently verifiable | Primitive: M3a ✅ · JIT events wired M3c ✅ · durability: **transactional outbox** (enqueue in-tx, background drain) closes the crash window ✅ (`credential.issued` post-fact append excepted) |
| Secrets (CA keys, target creds) read at rest | Envelope encryption: per-secret AES-256-GCM DEK wrapped by a master KEK (`VAULT_MASTER_KEY`; KMS-pluggable); sealed bytes never leave the DB/API; fail-closed `Open` | Implemented (M3d) |
| Master key lost/leaked | Losing `VAULT_MASTER_KEY` loses all sealed secrets (no recovery); KMS custody is the future seam — treat the key as a top-tier operational secret | Residual (documented; KMS deferred) |

## Related

- [access-model.md](access-model.md) — who can do what, and the visibility tiers.
- [capabilities.md](capabilities.md) — the capability vocabulary and the
  decide/enforce split.
- [architecture.md](architecture.md) — Approach A, continuous revocation, audit.
- [data-model.md](data-model.md) — the tables behind all of the above.
- [decisions.md](decisions.md) — rationale for the auth, audit, and data-plane
  choices.
