# Security & threat model

The consolidated security posture of jumpgate — what it defends, how, and which
mechanisms are implemented versus planned. This page **references** the detailed
treatments elsewhere ([access-model.md](access-model.md),
[architecture.md](architecture.md), [capabilities.md](capabilities.md),
[decisions.md](decisions.md)) rather than duplicating them.

> **Status:** several mechanisms are implemented today (existence-hiding, the
> opaque-token auth model, capability validation, the audit primitive); the
> data-plane enforcement, continuous revocation, and secrets-at-rest are
> **planned** (M3c/M3d/M4/M5). Each item below is marked.

## Posture — what we defend

- **Least privilege by construction.** Access is **requestable + approval-gated +
  JIT time-boxed**: nothing is standing unless an admin binds it, and powerful
  roles are reachable only through an approval flow that travels with the role
  (see [access-model.md](access-model.md#approval--how-a-requestable-role-gets-activated)).
  🟡 Approval **policy** resolution implemented (M3b); the request→grant→expiry
  **workflow** is M3c.
- **Agentless L7 gateway.** No software is installed on target hosts; the proxy
  terminates the protocol and injects credentials at the edge
  ([decisions.md](decisions.md)). ⬜ Data plane planned (M4/M5).
- **Centralized security-critical state ("Approach A").** The vault, policy, and
  grants live in warden (Go); the data plane holds a credential only for the life
  of an authorized session
  ([architecture.md](architecture.md#data-plane-interaction-model-approach-a)).

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
connect. This is a load-bearing design constraint spanning the **M3c reaper** and
the **M4 gateway/worker session registry** — full treatment in
[architecture.md](architecture.md#continuous-revocation--live-session-teardown-m3c-reaper--m4-gateway).
**Planned** (M3c/M4).

## Tamper-evident audit

Every security-relevant event is appended to a **hash-chained, append-only**
audit log: `entry_hash = sha256(prev_hash ‖ canonical(entry))`, so any
after-the-fact edit or deletion breaks the chain and is detectable
(`Verify`). Forced session terminations will be audited alongside the revocation
that caused them (with the teardown path, M3c/M4). The append/verify **primitive is implemented** (M3a); **wiring it
across every event** (requests, approvals, grants, session start/stop, teardown)
is **ongoing** as those subsystems land. See
[architecture.md](architecture.md#audit--recording).

## Secrets at rest

The **CredentialBroker** will **envelope-encrypt** the secrets it holds — CA
private keys and stored target secrets — under a master key (**NaCl secretbox**
in M3; a **pluggable KMS** later). Decryption happens only to hand a credential
to a worker for a live, authorized session. **Planned** (M3d).

## Threat-model summary

| Threat | Mitigation | Status |
|---|---|---|
| Attacker maps infrastructure by probing | Existence-hiding: catalog returns only visible assets; invisible lookup → `CodeNotFound`, never `403` | Implemented (M2) |
| Stolen/leaked bearer token used indefinitely | Opaque DB-backed hashed tokens with expiry; instant server-side revocation | Implemented (M2b) |
| Privilege creep / broad standing access | Requestable + approval-gated + JIT time-boxed; approval gate travels with the role | Policy: M3b ✅ · workflow: M3c ⬜ |
| Over-broad capability grant slips in unnoticed | Grammar validation at role creation; `**` is the explicit, auditable "whole scope"; `CapMatch` fails closed | Implemented (this branch) |
| Access revoked but live session continues | Continuous revocation → forced session teardown (push/pull re-eval of `HoldsRole`/grant) | Planned (M3c/M4) |
| Credential exposed on a compromised target | Agentless: no credential/software on targets; worker holds it only for a live session | Planned (M4/M5) |
| Audit log tampered to hide activity | Hash-chained append-only log; independently verifiable | Primitive: M3a ✅ · full wiring ongoing |
| Secrets (CA keys, target creds) read at rest | Envelope encryption (NaCl secretbox master key; KMS pluggable) | Planned (M3d) |

## Related

- [access-model.md](access-model.md) — who can do what, and the visibility tiers.
- [capabilities.md](capabilities.md) — the capability vocabulary and the
  decide/enforce split.
- [architecture.md](architecture.md) — Approach A, continuous revocation, audit.
- [data-model.md](data-model.md) — the tables behind all of the above.
- [decisions.md](decisions.md) — rationale for the auth, audit, and data-plane
  choices.
