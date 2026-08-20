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
- **JIT / request engine (AccessRequestService)** ✅ (M3c) — the full runtime lifecycle: `RequestAccess` (self-service at `required_approvals=0`), `Approve`/`Deny` (N-of-M, distinct approvers, one deny rejects, atomic mint under a row lock), `Cancel`, `RevokeGrant`, `ListMyRequests`/`ListPendingApprovals`/`ListMyGrants`/`ListGrants`. Approved requests mint a **time-boxed `access_grants` row** that joins the authorizer's held closure; an in-process **reaper** (`ReaperInterval`) expires grants. Live-session **teardown** is a wired **`GrantTerminator` seam** — the real grant-keyed `dataplane.Terminator` as of M4a (`live_sessions` re-eval + `LISTEN/NOTIFY`); the standing-eligibility cascade and worker mTLS are M4b/M4d.
- **Request policies** ✅ (M3b + Access-Model v2) one `request_policies` row per (role, scope) whose **existence makes the role requestable** there: role-level default (set at role definition — gates custom roles like `cluster-admin` to approval-only) + per-scope override, most-specific wins. Symmetric eligibility — requester = holders of `requester_role` on the scope ∪ explicit `requester` subjects; approver = holders of `approver_role` ∪ explicit `approver` subjects; both resolved **standing-only** via `HoldsRoleStanding` (a JIT grant confers access but never governance). No policy ⇒ not requestable. A policy also carries `required_approvals` (`≥ 0`; `0` = self-service) and a nullable `max_duration` grant cap. CRUD in `AccessService`; resolver (`EffectiveRule`, `IsApprover`, `IsEligibleRequester`) + `ResolveApproval` in `AccessRequestService`.
- **Audit log** 🟡 (M3a) hash-chained tamper-evident audit log (`entry_hash = sha256(prev_hash ‖ canonical(entry))`); append-only with advisory-lock genesis; chain independently verifiable (Append/Verify).
- **Recording service** ⬜ — session blobs to object store; metadata + hashes in Postgres.
- **Worker registry** ⬜ — watches k8s Endpoints; feeds the gateway its roster.
- **Token minter** ✅ (M4a) — short-lived Ed25519-signed session tokens bound to a grant, minted by `CreateSession`; the signing key is DB-backed (sealed at rest) and initialized via the admin `InitSessionKey` RPC. Each admitted session is recorded in the durable **`live_sessions`** ledger.

Chosen for the Kubernetes operator ecosystem (kubebuilder/controller-runtime),
mature ReBAC engines (OpenFGA), enterprise SSO breadth, and team velocity.

### Gateway — Rust ✅ (M4b)

The only externally exposed component: a thin, protocol-agnostic, **session-aware
load balancer**. A client opens TLS and sends **HTTP CONNECT** with the session
token in `Authorization: Bearer`; the gateway **verifies the PASETO token offline**
(signature + expiry, and reads `proto` for routing — it does NOT check `cnf`, the
worker does), picks a healthy worker (least in-flight, capacity-capped) from the
`WatchWorkers` roster, **mTLS-dials** it (pinning the worker's `spiffe://jumpgate/
worker/<id>` identity), forwards the CONNECT, and **pins** a `copy_bidirectional`
byte pump for the connection's life. It never terminates SSH/Postgres/RDP — that
protocol independence is what lets each worker be written in the best language for
its protocol. It is **teardown-unaware**: a warden `Teardown` force-closes the
worker's session and the pump collapses on EOF. Built on tokio + rustls. Internal
mTLS uses a **warden-rooted `mesh` CA**; component identity is a URI SAN, and
warden derives the authoritative `worker_id` from the peer cert (closing the M4a
self-asserted-identity gap). Bootstrap: `warden mesh-cert` provisions component
certs; the gateway fetches the token verification key via `GetSessionVerificationKey`.
Mesh identities are the 3-part form `spiffe://jumpgate/<role>/<id>` — workers
`spiffe://jumpgate/worker/<worker_id>`, gateway `spiffe://jumpgate/gateway/<id>`,
and warden **must** be minted with the SPIFFE id the gateway pins: canonical
default `spiffe://jumpgate/warden/warden` (override via `WARDEN_MESH_SPIFFE`),
minted with `warden-meshcert -spiffe spiffe://jumpgate/warden/warden`.
The real ssh-proxy worker + `jumpgate connect` CLI are **M4c** (M4b tests against a
stub worker).

### Protocol workers — Rust (`ssh-proxy` ✅ · others ⬜)

Stateless enforcers, one Deployment per protocol, scaled independently by replica
count. Each terminates its protocol, calls the control plane over gRPC for the
target address + just-in-time credential, injects the credential, proxies, and
(later) records the session. Because they sit behind the language-agnostic
gateway, future workers may be Go (e.g. `k8s-proxy` on client-go). Planned:
`pg-proxy` (pgwire + sqlparser-rs), and beyond that RDP/k8s.

**`ssh-proxy` (russh)** ✅ — the SSH worker registers with the control plane over
mesh mTLS (advertising its data-plane address, protocol, and capacity), then
accepts the gateway's tunnelled connection (reading the `CONNECT` preamble to
recover the session token) and runs an SSH **server** on it. The connection is a
**two-hop, key-separated** exchange:

- The client authenticates to the worker with its ephemeral key **Kc** (whose
  fingerprint is bound into the session token). The worker's publickey-auth
  callback calls the control plane's session-setup RPC, which verifies that
  binding, re-checks the caller's live entitlement, and issues a short-lived SSH
  **certificate** — over a fresh key **Kw** the worker generates per session. The
  worker accepts only if setup succeeds and the requested login is among the
  certificate's principals.
- The worker then opens an SSH **client** to the target, authenticating with
  **Kw + the certificate**, and proxies the channels (pty/shell/exec,
  window-resize, exit status) between the two hops.

Because the worker holds Kw's private key, it — not the client — authenticates the
target hop; the client's key never reaches the target. Terminating SSH at the
worker is also what will let it record sessions. A control-plane teardown signal
force-closes the live session; the worker reports the session's end, closing the
loop on continuous revocation for SSH.

### Client — `jumpgate` CLI ✅ (Go)

`jumpgate connect <login>@<asset>` is the user entry point. It authenticates to the
control plane (`jumpgate login` stores an opaque bearer token), resolves the asset,
generates the ephemeral key **Kc**, and requests a session — receiving a
short-lived admission token and the gateway address. It dials the gateway over TLS,
performs an HTTP `CONNECT` carrying the token, and then runs an embedded SSH client
(`golang.org/x/crypto/ssh`) over the resulting tunnel: an interactive pty with raw
local terminal mode, window-resize forwarding, and the remote exit code propagated.
The tunnel is already mutually authenticated all the way to the pinned worker
(client→gateway TLS, gateway→worker mesh mTLS), so the inner SSH host-key check is a
deliberate no-op.

Beyond `connect`, the CLI covers the full product surface: **admin** (`users`,
`groups`, `folders`, `assets ssh create/login/list/get`, `roles`, `bindings`, `policies`),
**access requests** (`access request/list/approve/deny/grants`), and **recordings**
(`recordings list/get/download` — the last fetching a presigned URL to a local
`.cast`). Every command maps to a warden ConnectRPC service and takes a global
`-o table|json` (creates print the new object's id, so flows script cleanly). Config
is a small hand-rolled file (`~/.config/jumpgate/config.json`) with **kubectl-style
named contexts** (`login --context NAME`, `config use-context`) so multiple
identities coexist; resolution is flag > env > current context. An old single-token
config migrates transparently into a `default` context.

### Shared mesh library (`jumpgate-mesh`, Rust) ✅

The gateway and workers share one Rust crate for the internal mTLS mesh: the
certificate verifiers that verify a peer's chain to the mesh CA and **pin its
SPIFFE identity** (`spiffe://jumpgate/<role>/<id>`), the `CONNECT` framing, and the
generated gRPC client stubs. Keeping the security-critical verifier in a single
place avoids drift between the components that depend on it.

### Data-plane interaction model ("Approach A")

The control plane **brokers**; workers **enforce**. Security-critical state (vault,
policy, grants) stays centralized in Go; the Rust data plane holds a credential
only for the duration of a live, authorized session. Revocation is immediate
(workers introspect the grant at session start; grant deletion tears sessions down).

### Continuous revocation — live-session teardown 🟢 (M3c reaper ✅ + M4a terminator ✅ + M4b worker mTLS ✅ + M4d cascade ✅)

> **Built.** The M3c side re-evaluates authorization on grant revocation/expiry (a
> revoked/expired grant stops conferring immediately, since the held closure filters
> `revoked_at IS NULL AND expires_at > now()`), audits the event, and calls the
> **`GrantTerminator` teardown seam**. As of **M4a** that seam is the **real**
> grant-keyed `dataplane.Terminator`: it re-evaluates the closure and, for sessions
> in the durable **`live_sessions`** ledger whose authorization no longer holds,
> pushes teardown to the owning worker stream via **`LISTEN/NOTIFY`** (a warden-node
> fan-out to the in-memory session registry). **M4d** closes the loop for
> **standing** authorization: teardown now ALSO fires when a role binding, group
> membership, role-rewrite rule, or role capability is removed, or a user is
> deactivated — not only when a grant is reaped. Changes are detected via database
> change notifications, with a periodic re-evaluation **sweep** as a backstop; a
> **worker-presence heartbeat** reconciles orphaned sessions and stuck teardowns.

**Authorization is continuous, not connect-time only.** A session is authorized
for its whole lifetime, not just at the handshake. When the authorization a live
session depends on is revoked, that session must be **terminated**, not merely
blocked at the *next* connect. "Zero standing access" is only true if losing
access ends access *now*.

**Revocation sources** that must trigger teardown of any dependent live session:

| Source | Change |
|---|---|
| JIT grant | expires (the M3c reaper) or is revoked (manual · self · approver · deactivation) — **built**; the real grant-keyed teardown fires (M4a `dataplane.Terminator`) |
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
after marking revoked + auditing), **M4a** (the seam's **real** grant-keyed
implementation: `live_sessions` ledger + closure re-eval + `LISTEN/NOTIFY` to the
owning worker stream — **built**), **M4b** (worker/gateway **mTLS** transport with
cert-SAN-derived authoritative `worker_id` — **built**), and **M4d** (the
eligibility-change cascade + pull-sweep for standing bindings/memberships/rewrites).
The **session ↔ grant mapping** (`live_sessions`) and the **teardown push** now
exist, making this invariant real for grant-keyed revocation rather than
aspirational.

**First-boot key init.** The session-token signing key is loaded **once at boot**.
On a fresh deploy the sequence is: start warden (sessions disabled — it logs a
warning) → admin calls **`InitSessionKey`** (and `InitCA ssh`) → **restart warden**
so it unseals the active key and enables `CreateSession` / `SetupSession`. A future
task can hot-load the key; that is out of scope here.

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

`CredentialBroker.Issue(ctx, userID, assetID, {Login, ClientSSHPubKey, ValidUntil,
KeyID})` (`warden/internal/vault`) is an **internal Go seam — not an RPC**. SSH auth
is **per-login**: it loads the asset's `ssh_asset_login` rows, enforces the
`ssh:login:<Login>` capability for the requested `Login` (uniformly, for every kind),
then runs the provider for that login's `kind`:

- **ca** (`kind='ca'`): signs `ClientSSHPubKey` with the SSH CA into an SSH **user
  cert** with **host-scoped principals** (`ValidPrincipals = [login@<asset-path>,
  login@<asset-id>]`), `ValidBefore = ValidUntil`, audit `KeyId`. Returns
  `{Kind:"ssh-cert"}`. The cert binds the login to the specific asset: targets
  accept it via an `AuthorizedPrincipalsFile` listing the expected principal(s)
  for each login (`<login>@<asset-path>` is the stable, human-readable form
  automation writes into the file; `<login>@<asset-id>` is the UUID form for
  rename-safety). The worker validates that every `ValidPrincipal` is of the
  form `<login>@<scope>`, binding the login identity before forwarding to the
  target — the target then enforces the host-binding through the
  `AuthorizedPrincipalsFile` check.
- **password** (`kind='password'`): `Open`s the login's linked `asset_secret` and
  returns `{Kind:"ssh-password"}` (the plain password bytes).
- **key** (`kind='key'`): `Open`s the login's linked `asset_secret` and returns
  `{Kind:"ssh-key"}` (the OpenSSH private-key PEM).
- **x509** provider: mints a short-lived client cert (CN = user identity, `NotAfter
  = ValidUntil`) via the X.509 CA. **Built + tested, not reachable via a kind yet.**

The stored secret is **plain** (just the password or private key); the username is the
login and the kind lives in the `ssh_asset_login` row. A login's `secret_id` is bound
by a composite FK to a secret **of the same asset**, so one asset's login cannot
reference another asset's secret.

`ValidUntil` / `KeyID` are **caller-supplied**; in M4 the worker passes the
granting `access_grant`'s remaining TTL and id so **a credential never outlives its
grant**. Every successful `Issue` appends a **`credential.issued`** audit event
(actor = user, subject = `asset:<id>`, details = provider / principals / key-id /
validity), post-fact and best-effort like the JIT events.

### Capability-driven SSH principals ✅ (Teleport-style)

The broker is the enforcement point for **which OS accounts a user may log in as**.
It does **not** trust the asset's login rows wholesale — the requested login must
survive the intersection with the user's live capabilities, for **every** kind
(ca/password/key), before any credential is minted:

```
allow(Login) ⇔ Login ∈ {rows of ssh_asset_login for asset}
             ∧ authz.Check(user, asset, "ssh:login:" + Login)
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
never the value**). Sealed private material never leaves the server.

SSH asset config lives on **`CatalogService`**, which owns the asset: a per-login
`logins[] {login, kind: ca|password|key, secret_id}` plus host key + target address.
`CreateAsset` takes an inline typed `config`, `GetAsset` returns the asset with its
config, and `UpdateAssetConfig` upserts it. The `jumpgate assets ssh` CLI drives it
(`create` / `login set --kind …` / `login list`); a `password`/`key` login seals its
secret via `VaultService.SetAssetSecret` and links it by `secret_id`.
`stored_secret_id` is a reference into the vault's `asset_secrets`; the sealed
bytes stay in the vault.

### Scope boundary — no live injection yet

M3d **builds + tests** the broker by calling `Issue` directly and asserting the
emitted cert/secret. It does **not** connect to hosts, inject into a session, or
wire the broker to a proxy — that (and the worker passing the grant TTL) is **M4**;
the `postgres`/`k8s` typed configs + their proxies are **M5**.

## Audit & recording 🟢 (M3a primitive ✅ · JIT events ✅ · SSH session recording ✅)

Every request, reason, approval, grant, session start/stop, step-up, and expiry is
written to an append-only, **hash-chained** audit log
(`entry_hash = sha256(prev_hash ‖ canonical(entry))`) so tampering breaks the
chain. The JIT workflow emits `access_request.created`/`.approved`/`.denied`/
`.cancelled` and `access_grant.activated`/`.revoked`/`.expired` (M3c), and the
vault emits `credential.issued` on each broker issuance (M3d). The JIT events are
written through a **transactional outbox**: each service `Enqueue`s its event into
`audit_outbox` inside the same domain tx (atomic with the state change), and a
background drainer chains outbox rows into the hash-linked log — closing the
post-commit crash window (see [security.md](security.md#tamper-evident-audit)).
The vault's `credential.issued` is a post-fact append (no domain tx to join) and
still uses direct `Append`.

**SSH session recording.** SSH sessions are recorded by default at the terminating
worker in **asciicast v2** (both directions of I/O plus terminal resizes, with
timing — replayable with `asciinema play`). Recording is **mandatory unless** the
subject holds the `ssh:record:exempt` capability on the asset; warden decides this
at session setup and tells the worker, which **fails closed** — if a required
recording cannot be established or a mid-session write fails, the session is refused
or torn down. The worker streams the recording directly to S3-compatible object
storage via multipart upload (parts flushed as the session runs, so a crash loses at
most the last part), maintaining a rolling SHA-256. On completion it reports
`{object_key, size, sha256, status}` to warden, which persists a `session_recordings`
row and emits `recording.completed`/`recording.failed` into the hash-chained log.
Admins retrieve a recording through the `RecordingService` (list/get and a
short-lived **presigned GET URL**, audited as `recording.accessed`). The object key
is protocol-partitioned (`recordings/ssh/<date>/<session_id>.cast`) so one bucket can
serve other protocols later. Postgres statement-log recording, other protocols, a
web replay player, and SIEM export are later milestones.

## Running on Kubernetes (kind)

The whole stack runs on a local [kind](https://kind.sigs.k8s.io/) cluster from a
Helm chart, so the control plane, gateway, and an ssh-proxy worker can be exercised
end-to-end without any hand-wired certificates or processes.

- **Chart — `deploy/helm/jumpgate`.** Renders warden, the gateway, and one
  ssh-proxy worker, plus their Services, Secrets, and mesh Certificates. warden's
  user API and the gateway's external listener are exposed as fixed NodePorts; the
  kind cluster (`test/env/cluster.yaml`) forwards them to `localhost:8080`
  (warden) and `localhost:8443` (gateway) so the host CLI can reach them directly.
- **Mesh certificates via cert-manager.** The chart provisions a cert-manager
  `Issuer` rooted at warden's mesh CA and issues each mesh peer (gateway, worker,
  warden's own data-plane listener) a certificate with its canonical
  `spiffe://jumpgate/<role>/<id>` URI SAN — the same identity the gateway pins when
  it dials. The gateway's **external** TLS is a separate cert whose CA
  (`jumpgate-gateway-ext` secret, key `ca.crt`) the CLI must trust to verify the
  data-plane tunnel; `make kind-demo` exports it to `./jumpgate-mesh-ca.pem`.
- **`warden-bootstrap` pre-install Job.** A Helm pre-install hook Job initializes
  the one-time cluster state the RPCs cannot bootstrap themselves: it seals the
  vault master key, mints warden's mesh CA and session-signing key, creates the
  bootstrap admin (`admin@demo.test` in the demo values), and publishes the SSH
  user CA's public key as a Secret the ssh test workload mounts.
- **Toggleable in-cluster dependencies.** `postgres.enabled` runs an in-cluster
  Postgres for warden's data (set it false and point `warden.databaseUrl` at an
  external database); `silo.enabled` runs an in-cluster S3-compatible object store
  for session recordings (disable it to use any external S3 endpoint).
- **Independent sshd test workload — `test/env/testworkload`.** A minimal sshd
  Deployment (`ssh-target` Service) that trusts the bootstrap SSH user CA. It is a
  *target*, not part of jumpgate, and is applied separately from the chart so the
  chart stays deployment-agnostic.
- **Make targets.** `make kind-up` creates the cluster, installs cert-manager and
  the chart, and deploys the sshd workload; `make kind-demo` also exports the mesh
  CA and prints the CLI setup; `make kind-e2e` runs the Go e2e suite (`test/e2e`)
  against the live stack — a three-actor cross-approval scenario driving the real
  CLI (admin onboards an SSH asset and a request policy; two users request and
  approve each other's access; one connects and runs a command; the admin auditor
  downloads the recording and confirms it captured the session) — and tears the
  cluster down (`KEEP=1` to keep it).

## Key technology choices

See [decisions.md](decisions.md) for the rationale behind Go+Rust, the two-tier
data plane, agentless posture, OpenFGA, PASETO, and the frontend stack.
