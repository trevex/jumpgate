# Architecture

> **Status legend:** ✅ implemented · 🟡 partial · ⬜ planned. As of milestone
> **M2a**, the foundation plus the access-model data layer and authorization
> resolution are implemented (control plane); the components below describe the
> target architecture with per-item status.

## Vision

jumpgate provides secure, audited, **just-in-time** access to infrastructure —
Kubernetes, VMs (SSH + RDP), databases, and generic HTTP/APIs — without
installing agents on the targets. The core bet is **zero standing access**:
nothing is granted until requested; access is time-boxed, approval-gated,
credential-injected, fully recorded, and auto-expiring.

## The three planes

```
                    ┌──────────────── Control plane (Go) ──────────────┐
                    │ identity · Authorizer seam (SQL CTEs) · roles/bindings│
                    │ request policies · JIT grants · vault · audit ·  │
                    │ recording metadata · worker-pool registry       │
                    └──────▲───────────────▲──────────────────▲────────┘
              token mint /  │     gRPC:     │ authz + creds    │ recording /
              introspection │  pool roster  │ + approvals      │ audit events
                     ┌──────┴──────┐        │                  │
   client ────TLS───►│   Gateway   │  (only externally exposed component;
 (CLI / browser)     │   (Rust)    │   thin, protocol-agnostic session router)
                     └──────┬──────┘
                            │ forwards the pinned session stream to a worker
          ┌─────────────────┼───────────────────┐
     ┌────▼─────┐     ┌──────▼─────┐     (planned: rdp-proxy [Rust],
     │ ssh-proxy│     │  pg-proxy  │             k8s-proxy [Go], …)
     │  (Rust)  │     │   (Rust)   │
     └────┬─────┘     └──────┬─────┘
          └──────── inject creds · proxy · record ───────┘
                            │
                      target assets
```

### Control plane — Go ✅ (skeleton) / ⬜ (features)

The single source of truth and the brain. Serves the REST API + embedded web UI.
Modules (all ⬜ except the HTTP skeleton):

- **API server** ✅ ConnectRPC (connect-go): AuthService + IdentityService + CatalogService + AccessService + AccessRequestService served on the same HTTP server as /healthz; one handler speaks Connect + gRPC + gRPC-Web (no proxy). Auth via a bearer-token interceptor; validation via protovalidate; existence-hiding via CodeNotFound.
- **Identity** 🟡 (M2b: local users/groups/nested memberships + password login/opaque tokens + admin guard; OIDC/SAML/SCIM later). Initial admin seeded via `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` on first startup.
- **Authorization** ✅ (recursive-CTE Authorizer + catalog RPCs; OpenFGA remains a future drop-in behind the seam). See [Access model](#access-model).
- **Access config (AccessService)** ✅ — all admin authorization config in one surface: custom **roles** (capability bundles), **role_grants** (the `same_object`/`parent` rewrite rules), **role_bindings** (standing-only), **request_policies** + requester/approver **subjects**, and `ExplainRole`.
- **Resource catalog** ✅ folders/assets CRUD + per-user visibility catalog (CatalogService): ListVisibleAssets / GetAssetAccess resolve the caller's Active/Requestable/Invisible tiers via the Authorizer, with CodeNotFound existence-hiding. All role/authz config lives in AccessService.
- **Credential vault / CredentialBroker** ✅ (M3d) — envelope-encrypted secrets at rest (per-secret AES-256-GCM DEK wrapped by a master KEK, KMS-ready), an SSH user CA + an X.509 client CA, and the **`CredentialBroker`** seam that mints a short-lived credential for a (user, asset) with **capability-driven SSH principals**. Admin surface is `VaultService`. **This completes M3.** The broker is built + tested but not yet wired to a live session — the worker calling `Issue` and live credential **injection** are **M4**. See [Vault / CredentialBroker](#vault--credentialbroker-m3d).
- **JIT / request engine (AccessRequestService)** ✅ (M3c) — the full runtime lifecycle: `RequestAccess` (self-service at `required_approvals=0`), `Approve`/`Deny` (N-of-M, distinct approvers, one deny rejects, atomic mint under a row lock), `Cancel`, `RevokeGrant`, `ListMyRequests`/`ListPendingApprovals`/`ListMyGrants`/`ListGrants`. Approved requests mint a **time-boxed `access_grants` row** that joins the authorizer's held closure; an in-process **reaper** (`ReaperInterval`) expires grants. Live-session **teardown** is a wired **`GrantTerminator` seam** (no-op now; real gateway kill is M4).
- **Request policies** ✅ (M3b + Access-Model v2) one `request_policies` row per (role, scope) whose **existence makes the role requestable** there: role-level default (set at role definition — gates custom roles like `cluster-admin` to approval-only) + per-scope override, most-specific wins. Symmetric eligibility — requester = holders of `requester_role` on the scope ∪ explicit `requester` subjects; approver = holders of `approver_role` ∪ explicit `approver` subjects; both resolved **standing-only** via `HoldsRoleStanding` (a JIT grant confers access but never governance). No policy ⇒ not requestable. A policy also carries `required_approvals` (`≥ 0`; `0` = self-service) and a nullable `max_duration` grant cap. CRUD in `AccessService`; resolver (`EffectiveRule`, `IsApprover`, `IsEligibleRequester`) + `ResolveApproval` in `AccessRequestService`.
- **Audit log** 🟡 (M3a) hash-chained tamper-evident audit log (`entry_hash = sha256(prev_hash ‖ canonical(entry))`); append-only with advisory-lock genesis; chain independently verifiable (Append/Verify).
- **Recording service** ⬜ — session blobs to object store; metadata + hashes in Postgres.
- **Worker registry** ⬜ — watches k8s Endpoints; feeds the gateway its roster.
- **Token minter** ⬜ — short-lived PASETO v4 session tokens bound to a grant.

Chosen for the Kubernetes operator ecosystem (kubebuilder/controller-runtime),
mature ReBAC engines (OpenFGA), enterprise SSO breadth, and team velocity.

### Gateway — Rust ✅ (skeleton)

The only externally exposed component: a thin, protocol-agnostic, **session-aware
load balancer**. It validates the control-plane-signed session token, reads the
target protocol from the token framing, picks a healthy worker (least-sessions)
and **pins** the connection for its lifetime, then forwards the still-native byte
stream over internal mTLS. It never terminates SSH/Postgres/RDP — that protocol
independence is what lets each worker be written in the best language for its
protocol. Built on tokio + rustls. M1 implements a `/healthz` axum surface only.

### Protocol workers — Rust ⬜

Stateless enforcers, one Deployment per protocol, scaled independently by replica
count. Each terminates its protocol, calls the control plane over gRPC for the
target address + just-in-time credential, injects the credential, proxies, and
records the session. MVP workers: `ssh-proxy` (russh) and `pg-proxy` (pgwire +
sqlparser-rs). Because they sit behind the language-agnostic gateway, future
workers may be Go (e.g. `k8s-proxy` on client-go).

### Data-plane interaction model ("Approach A")

The control plane **brokers**; workers **enforce**. Security-critical state (vault,
policy, grants) stays centralized in Go; the Rust data plane holds a credential
only for the duration of a live, authorized session. Revocation is immediate
(workers introspect the grant at session start; grant deletion tears sessions down).

### Continuous revocation — live-session teardown 🟡 (M3c reaper ✅ + M4 gateway ⬜)

> **Partly built.** The M3c side is done: grant revocation/expiry re-evaluates
> authorization (a revoked/expired grant stops conferring immediately, since the
> held closure filters `revoked_at IS NULL AND expires_at > now()`), audits the
> event, and calls a **`GrantTerminator` teardown seam** — wired to a **no-op**
> today. The load-bearing part still missing is the **M4** gateway/worker session
> registry and the real kill path that seam will drive.

**Authorization is continuous, not connect-time only.** A session is authorized
for its whole lifetime, not just at the handshake. When the authorization a live
session depends on is revoked, that session must be **terminated**, not merely
blocked at the *next* connect. "Zero standing access" is only true if losing
access ends access *now*.

**Revocation sources** that must trigger teardown of any dependent live session:

| Source | Change |
|---|---|
| JIT grant | expires (the M3c reaper) or is revoked (manual · self · approver · deactivation) — **built**; teardown seam called (no-op until M4) |
| Standing `role_binding` | deleted |
| `role_grants` rewrite rule | changed so it no longer confers the role (`HoldsRole` flips to false) |
| Group membership | a `group_memberships` row removed |
| Approval | a granted approval revoked |
| User | deactivated |

**Mechanism (Approach A).** warden (the control plane) is the source of truth
for authorization, so warden must **signal** the gateway/workers to kill sessions
when the effective authorization for a live session changes — via a **teardown
channel** on the worker ↔ control-plane contract, to be designed and added with
the gateway (M4; no such RPC exists yet). Workers map each **live session → the
grant/binding(s) it relies on** and support forced termination of a session by
that key. The trigger is a re-evaluation of
`HoldsRole` / grant validity:

- **push** — re-evaluate on a change event (a grant reaped, a binding/membership
  deleted) and signal teardown for any session whose authorization no longer
  holds; and/or
- **pull** — a periodic sweep that re-checks live sessions against current
  authorization.

**Every forced termination is an audit event** appended to the hash-chained log
(see [Audit & recording](#audit--recording)), alongside the revocation that
caused it.

**Scope.** This spans **M3c** (reaper → teardown *signal*: **built** — the reaper,
`RevokeGrant`, and the deactivation cascade all call the `GrantTerminator` seam
after marking revoked + auditing) and **M4** (gateway / worker **session registry**
+ kill path — the seam's real implementation, plus the eligibility-change cascade
for standing bindings/memberships/rewrites). Keeping the **session ↔ grant/binding
mapping** and the **teardown RPC** in scope for M4 is what makes this invariant real
rather than aspirational.

## Access model

Relationship-based (ReBAC), accessed through an **`Authorizer` seam**. The M2a implementation resolves access with **recursive SQL (CTEs) over Postgres** — computing transitive nested-group membership, the explicit folder cascade, and the Active/Requestable/Invisible tiers. As of **M3-roles + Access-Model v2**, folder cascade is uniformly **explicit**: a role reaches a folder's descendants only if it declares a `parent` role-rewrite rule (an explicit ReBAC-light userset-rewrite over `role_grants`, resolved by `HoldsRole`), not an automatic subtree walk — and the **same** `HoldsRole` predicate backs standing access *and* a RequestPolicy's requester/approver held-role checks. An OpenFGA-backed implementation (embedded or sidecar) can be dropped in behind the same seam later; the relationship rows are stored tuple-shaped to make that swap mechanical.

The model separates *what a role means* from *who holds it* — modeled on Kubernetes RBAC (Role + RoleBinding). 🟡 (M2a: resolution implemented; M2b: catalog RPCs)

1. **Capabilities** — a fixed vocabulary the workers enforce (`connect`, `read`,
   `write`, `ddl`, `admin`, connection identity, escalation knobs). Not user-editable.
2. **Role** — an admin-defined bundle of capabilities scoped to a resource type
   (e.g. *PG-Migrator*, *SRE-Prod-SSH*). This is the customer's "custom role".
3. **RoleBinding** — assigns a role to subjects at a scope (folder or asset).
   **Standing-only** (permanent, admin-granted). Requestability is *not* a binding.
4. **RequestPolicy** — one row per (role, scope) whose **existence makes the role
   requestable** there; it names who may request (`requester_role` ∪ explicit
   subjects) and the approval gate (threshold + `approver_role` ∪ subjects).

The recursive-CTE backend answers assignment/visibility/requestability (with nested groups
and the explicit folder cascade); the control plane resolves roles → capabilities.

**Discoverability is a permission.** Against any asset a user is *Active*
(holds a role now), *Requestable* (eligible to request ≥1 role via a policy, minus
already-active), or *Invisible* (existence undisclosed). The catalog is computed
server-side from the graph; requests for non-visible assets return **404, not
403**, so topology never leaks. See [access-model.md](access-model.md).

## Just-in-time access & escalation ✅ (M3b policy · M3c request→grant→reaper) / ⬜ (M5 inline)

**The request flow (M3c — built):** `RequestAccess(role, asset, duration, reason)`
→ the effective `request_policy(role, asset)` is resolved most-specific → the
requester's **eligibility** is checked (`IsEligibleRequester`: holds
`requester_role` on the asset **via a standing binding** ∪ explicit `requester`
subject) → a request is opened (blocking a duplicate pending request, or one where
the role is already held Active), **snapshotting** the required-approval count and
the clamped `granted_duration` → approvals are collected from the policy's approvers
(`IsApprover`: holds `approver_role` **standing** ∪ explicit `approver` subject),
**N-of-M** (distinct approvers, self-approval excluded, one deny rejects) → on the
threshold (or immediately for a self-service `required_approvals=0` policy) a
**time-boxed `access_grants` row** is written **atomically under a row lock**,
joining the requester's held set until it expires or is revoked; an in-process
**reaper** (`ReaperInterval`, 30s default) expires grants and audits/tears-down.
A JIT grant confers **access but not governance** — the requester/approver
predicates resolve standing-only, so a granted role can't be used to request or
approve further (no self-escalation). Every step is a hash-chained audit event.

One request engine, two timings:

- **Pre-session** — request a (higher-privilege) role before connecting. Used by
  **SSH** (the injected credential carries the privilege; no inline TTY gating,
  which is not a robust boundary).
- **Inline** — during a live session, a specific action pauses pending approval,
  then auto-resumes. Used by **Postgres**: `pg-proxy` classifies each statement to
  a privilege tier (`readonly`/`readwrite`/`ddl`); a statement above the current
  tier pauses and offers **Approve once** or **Elevate to tier X for N minutes**
  (a session-scoped, time-boxed step-up, enforced at the DB via `SET ROLE`).

A JIT grant is a temporary `access_grants` row (a role for a user at a scope) with
an expiry, reaped on timeout — the same primitive for a 2-hour SSH grant or a
15-minute Postgres step-up. It never mutates admin config (`role_bindings`); the
authorizer's held-closure base becomes `role_bindings ∪ active access_grants`
(M3c). A grant is revoked by **expiry** (the reaper), **manual `RevokeGrant`**
(admin · the subject/self-revoke · a standing approver for its (role, asset)), or
the **deactivation** of its subject — each audited and routed to the
`GrantTerminator` teardown seam.

## Vault / CredentialBroker ✅ (M3d) — completes M3

The vault is the boundary that turns "this user is authorized" into "here is the
short-lived credential to reach the target". Built + tested in **M3d**; the live
consumer (the worker calling it, credential **injection** into a session) is
**M4**. This section **completes M3**.

### Envelope encryption — the `secrets` package ✅

All CA private keys and stored secrets are **envelope-encrypted at rest**:

- A **master KEK** comes from config `VAULT_MASTER_KEY` (a base64-encoded **32-byte**
  key, not a passphrase). Built into a `secrets.Sealer` **once at startup**. If the
  key is **unset** the vault is **disabled** (boot + a `slog.Warn`; sealing write
  paths fail closed with `FailedPrecondition`); a **malformed** key is **fatal**.
- Each secret gets a fresh random **256-bit DEK** — `ct = AES-256-GCM(plaintext,
  DEK)`; the DEK is then **wrapped** by the KEK (`AES-256-GCM(DEK, KEK)`). `Seal`
  serializes `{version, wrapped_dek+nonces, ct+nonce}` into one `bytea`; `Open`
  reverses it. GCM gives tamper detection — a wrong KEK or a flipped byte fails
  `Open` (fail-closed).
- **KMS-ready:** only the DEK-wrap step is the KMS seam — a future KMS wraps/unwraps
  the DEK; master-key rotation re-wraps DEKs only, never the ciphertexts.

Plaintext CA keys / secrets **never** touch the DB unsealed, and sealed bytes are
**never** returned via the API. See [security.md](security.md#secrets-at-rest).

### Certificate authorities — the `ca` package ✅

Two global CA singletons, private material sealed into `ca_keys` (one **active**
per kind), initialized once via `VaultService.InitCA(kind)`:

- **SSH user CA** — ed25519. `public_material` = the `authorized_keys` CA line
  (hosts add it to `TrustedUserCAKeys` to trust warden-minted user certs).
- **X.509 client CA** — self-signed, ECDSA P-256. `public_material` = the CA cert
  PEM (mTLS services trust it). **Built + unit-tested but not reachable via any
  `assets.kind` yet** — Postgres/k8s wire it up in **M5**.

`GetCAPublic(kind)` distributes the public material to targets.

### The broker + providers ✅

`CredentialBroker.Issue(ctx, userID, assetID, {ClientSSHPubKey, ValidUntil,
KeyID})` (`warden/internal/vault`) is an **internal Go seam — not an RPC**. It
loads the asset (`kind`) → its typed config → runs the matching provider:

- **ssh-ca** (`ssh` asset, `auth_method='ca-cert'`): derives the entitled
  principals (below), signs `ClientSSHPubKey` with the SSH CA into an SSH **user
  cert** with `ValidPrincipals = principals`, `ValidBefore = ValidUntil`, and the
  audit `KeyId`. Returns `{Kind:"ssh-cert"}`.
- **stored-key / stored-secret** (`ssh` asset, `auth_method='stored-key'`): `Open`s
  the linked `asset_secret` and returns `{Kind:"secret"}` (no cert).
- **x509** provider: mints a short-lived client cert (CN = user identity, `NotAfter
  = ValidUntil`) via the X.509 CA. **Built + tested, not reachable via a kind yet
  (M5).**

`ValidUntil` / `KeyID` are **caller-supplied**; in M4 the worker passes the
granting `access_grant`'s remaining TTL and id so **a credential never outlives its
grant**. Every successful `Issue` appends a **`credential.issued`** audit event
(actor = user, subject = `asset:<id>`, details = provider / principals / key-id /
validity), post-fact and best-effort like the JIT events.

### Capability-driven SSH principals ✅ (Teleport-style)

The broker is the enforcement point for **which OS accounts a user may log in as**.
It does **not** trust the host's `allowed_logins` wholesale — it intersects that
list with the user's live capabilities:

```
principals = { L ∈ ssh_asset_config.allowed_logins
               : authz.Check(user, asset, "ssh:login:" + L) }
```

`Check` is the same glob-aware, grant-aware authorizer used everywhere: a role
holding `ssh:login:*` matches every allowed login; `ssh:login:root` matches just
`root`; the capability may be held via a standing binding **or** an active JIT
grant. An **empty** intersection is **refused** (`ErrNoLoginEntitlement` — no cert,
no audit) rather than defaulting to an all-accounts cert; the `ca` layer
**independently** refuses to sign a principal-less certificate as
defense-in-depth. So the minted cert authorizes **exactly** the logins the user is
entitled to — no static host login. See
[access-model.md](access-model.md#ssh-access--os-logins-are-capabilities-m3d).

### `GetAssetSecret` scoping ✅

The broker's stored-secret lookup is scoped to the owning asset (id **and**
`asset_id`), so a secret can never be opened for the wrong asset (fail-closed).

### Admin API — `VaultService` ✅

Admin-guarded ConnectRPC: `InitCA(kind)` / `GetCAPublic(kind)`; `SetAssetSecret` /
`DeleteAssetSecret` / `ListAssetSecrets` (**metadata only — id/name/created_at,
never the value**); `SetSSHAssetConfig` / `GetSSHAssetConfig`. `CatalogService.
CreateAsset` gains a validated `kind` (default `ssh`). Sealed private material
never leaves the server.

### Scope boundary — no live injection yet

M3d **builds + tests** the broker by calling `Issue` directly and asserting the
emitted cert/secret. It does **not** connect to hosts, inject into a session, or
wire the broker to a proxy — that (and the worker passing the grant TTL) is **M4**;
the `postgres`/`k8s` typed configs + their proxies are **M5**.

## Audit & recording 🟡 (M3a primitive ✅ · JIT events ✅ · sessions M4/M5)

Every request, reason, approval, grant, session start/stop, step-up, and expiry is
written to an append-only, **hash-chained** audit log
(`entry_hash = sha256(prev_hash ‖ canonical(entry))`) so tampering breaks the
chain. The JIT workflow emits `access_request.created`/`.approved`/`.denied`/
`.cancelled` and `access_grant.activated`/`.revoked`/`.expired` (M3c), and the
vault emits `credential.issued` on each broker issuance (M3d). Audit
appends are **post-commit** (the audit logger opens its own advisory-locked tx and
cannot join the domain tx), which leaves a small **crash window** between the domain
commit and the append — a known limitation, to be closed with a transactional
outbox (see [security.md](security.md#tamper-evident-audit)). Sessions are recorded
(SSH as asciicast v2; Postgres as a structured statement log) to object storage with
per-chunk hashes — later milestones (M4/M5). SIEM export is a later milestone.

## Key technology choices

See [decisions.md](decisions.md) for the rationale behind Go+Rust, the two-tier
data plane, agentless posture, OpenFGA, PASETO, and the frontend stack.
