# Architecture

jumpgate provides secure, audited, **just-in-time** access to infrastructure
without installing agents on the targets. The core bet is **zero standing
access**: nothing is granted until requested; access is time-boxed,
approval-gated, credential-injected, fully recorded, and auto-expiring — and when
the authorization behind a live session is revoked, the session is torn down, not
merely blocked at the next connect.

Today jumpgate proxies **SSH** end to end. The data plane is protocol-agnostic by
design; Postgres, Kubernetes, and RDP are additive workers and are called out as
**planned** where they appear.

## The three planes

```
                    ┌──────────────── Control plane (Go) ──────────────┐
                    │ identity · Authorizer (SQL CTEs) · roles/bindings │
                    │ request policies · JIT grants · vault · audit ·   │
                    │ recording metadata · worker registry             │
                    └──────▲───────────────▲──────────────────▲────────┘
              session-token │  mesh gRPC:   │ authz + creds    │ recording /
              verification  │  worker roster│ + session setup  │ audit events
                     ┌──────┴──────┐        │                  │
   client ────TLS───►│   Gateway   │  (only externally exposed component;
 (jumpgate CLI)      │   (Rust)    │   thin, protocol-agnostic session router)
                     └──────┬──────┘
                            │ forwards the pinned session stream to a worker
          ┌─────────────────┼───────────────────┐
     ┌────▼─────┐     ┌──────▼─────┐     (planned: pg-proxy, k8s-proxy,
     │ ssh-proxy│     │  pg-proxy  │             rdp-proxy)
     │  (Rust)  │     │  (planned) │
     └────┬─────┘     └────────────┘
          └──────── inject creds · proxy · record ───────┘
                            │
                      target assets
```

The control plane **brokers**, the data plane **enforces**. Security-critical
state (vault, policy, grants) stays centralized in Go; a Rust worker holds a
credential only for the duration of one live, authorized session.

## Control plane — Go

The single source of truth. It serves a ConnectRPC API (Connect + gRPC + gRPC-Web
on one handler, no proxy) alongside `/healthz`, authenticated by an interceptor
that accepts either an `Authorization: Bearer <token>` header (CLI) or an
`httpOnly` `jumpgate_session` cookie with `Sec-Fetch-Site: same-origin` (browser —
fail-closed CSRF gate), validated by protovalidate, and existence-hiding via
`CodeNotFound`. A second, mutually-authenticated listener serves the internal mesh
(the data-plane and gateway contracts).

**Services.** The API is split into focused ConnectRPC services:

| Service | Responsibility |
|---|---|
| `AuthService` | password login → opaque bearer token (`cookie_only=false`, CLI) or `httpOnly` session cookie (`cookie_only=true`, browser); `WhoAmI` (identity + global capabilities for nav gating); `Logout` (revoke token + clear cookie) |
| `IdentityService` | users, groups, nested memberships, user lifecycle; path-scoped `ListGroups` (visibility-filtered, keyset-paginated) + `GetGroupAccess` (capabilities on selection) |
| `CatalogService` | folders & assets (incl. typed SSH config); path-scoped `ListFolders`/`ListAssets` (visibility-filtered, keyset-paginated) + `GetAssetAccess`/`GetFolderAccess` (capabilities on selection) + `ListFolderContents` (bounded per-kind aggregator) + `Resolve*` |
| `AccessService` | all authorization config: roles, role-grants, standing role-bindings, request policies + subjects, `ExplainRole`; path-scoped `ListRoles` (visibility-filtered, keyset-paginated) + `GetRoleAccess` (capabilities on selection) |
| `AccessRequestService` | the JIT runtime: request / approve / deny / cancel / revoke, grants, approval resolution |
| `VaultService` | CA init & public material, mesh CA + cert issuance, session-signing-key init, asset secrets (metadata only on read) |
| `RecordingService` | list / get / presigned-download of session recordings |
| `SessionService` | `CreateSession` — mints a data-plane admission token for an authorized (user, asset) |
| `GatewayService` | `WatchWorkers` roster stream + `GetSessionVerificationKey` for the gateway |
| `Dataplane` (mesh) | worker registration/heartbeat stream + `SetupSession` |
| `HealthService` | liveness |

**Authorization is capability-only.** There is no admin flag. Every management RPC
is gated by a capability check at the relevant scope (`requireCap`); the bootstrap
admin is an ordinary user holding an `admin` role whose single capability is `**`,
bound globally. See [capabilities.md](capabilities.md) and
[access-model.md](access-model.md).

**Persistence.** Postgres via sqlc + pgx, with goose migrations embedded in the
binary and applied on startup. The `Authorizer` seam is backed by recursive SQL
CTEs; an OpenFGA-backed backend could be dropped in behind the same seam later, so
the relationship rows are stored tuple-shaped.

## Data plane

### Gateway — Rust

The only externally exposed component: a thin, protocol-agnostic, **session-aware
load balancer** built on tokio + rustls. A client opens TLS and sends an **HTTP
CONNECT** with its session token in `Authorization: Bearer`. The gateway
**verifies the PASETO token offline** (Ed25519 signature + expiry, and reads the
`proto` claim for routing — it does *not* check the client-key binding `cnf`; the
worker does), picks a healthy worker (least in-flight, capacity-capped) from the
`WatchWorkers` roster, **mTLS-dials** it while pinning the worker's
`spiffe://jumpgate/worker/<id>` identity, forwards the CONNECT, and pins a
`copy_bidirectional` byte pump for the connection's life.

It never terminates SSH/Postgres/RDP — that protocol independence is what lets
each worker be written in the best language for its protocol. It is
**teardown-unaware**: when warden force-closes a worker's session, the pump
collapses on EOF.

### Protocol workers — Rust

Stateless enforcers, one Deployment per protocol, scaled independently by replica
count. Each terminates its protocol, calls the control plane over the mesh for the
target address and a just-in-time credential, injects the credential, proxies, and
records the session. Because they sit behind the language-agnostic gateway, a
future worker may be Go (e.g. a `k8s-proxy` on client-go).

**`ssh-proxy` (russh) — live.** The SSH worker registers with the control plane
over mesh mTLS (advertising its data-plane address, protocol, and capacity), then
accepts the gateway's tunnelled connection (reading the `CONNECT` preamble to
recover the session token) and runs an SSH **server** on it. The exchange is
**two-hop and key-separated**:

- The client authenticates to the worker with its ephemeral key **Kc** (whose
  fingerprint is bound into the session token). The worker's publickey-auth
  callback calls `SetupSession`, which verifies that binding, re-checks the
  caller's live entitlement, records the session, and returns a credential for the
  target hop — over a fresh key **Kw** the worker generates per session. The worker
  accepts only if setup succeeds and the requested login is authorized.
- The worker then opens an SSH **client** to the target and proxies the channels
  (pty/shell/exec, window-resize, exit status) between the two hops.

Because the worker holds Kw's private key, it — not the client — authenticates the
target hop; the client's key never reaches the target. A control-plane teardown
signal force-closes the live session, and the worker reports the session's end.

Planned workers: `pg-proxy` (pgwire + a SQL parser, with inline per-statement
step-up), and beyond that Kubernetes and RDP.

### Shared mesh library — `jumpgate-mesh` (Rust)

The gateway and workers share one crate for the internal mTLS mesh: the verifiers
that check a peer's chain to the mesh CA and **pin its SPIFFE identity**
(`spiffe://jumpgate/<role>/<id>`), the `CONNECT` framing, and the generated gRPC
client stubs. Keeping the security-critical verifier in one place avoids drift
between the components that depend on it.

### Client — `jumpgate` CLI (Go)

`jumpgate connect <login>@<asset>` is the user entry point. The `<asset>` is a
**DNS-style dotted path** (leaf-first, e.g. `pg-primary.db.prod`) or a UUID; the
CLI sends it to `CatalogService.ResolveAsset`, which performs an access check and
returns the id — an unknown reference and one the caller cannot see both return
`NotFound`, hiding existence.

`connect` authenticates to the control plane (`jumpgate login` stores an opaque
bearer token), resolves the asset, generates the ephemeral key **Kc**, and calls
`CreateSession` — receiving a short-lived admission token and the gateway address.
It dials the gateway over TLS, performs an HTTP `CONNECT` carrying the token, and
runs an embedded SSH client (`golang.org/x/crypto/ssh`) over the resulting tunnel:
an interactive pty with raw local terminal mode, window-resize forwarding, and the
remote exit code propagated. The tunnel is already mutually authenticated all the
way to the pinned worker (client→gateway TLS, gateway→worker mesh mTLS), so the
inner SSH host-key check is a deliberate no-op.

Beyond `connect`, the CLI covers the full product surface: **admin** (`users`,
`groups`, `folders`, `assets ssh create/login/list/get`, `roles`, `bindings`,
`policies`), **access requests** (`access request/list/approve/deny/grants`), and
**recordings** (`recordings list/get/download` — the last fetching a presigned URL
to a local `.cast`). Every command maps to a warden ConnectRPC service and takes a
global `-o table|json`. Config is a small hand-rolled file
(`~/.config/jumpgate/config.json`) with **kubectl-style named contexts**
(`login --context NAME`, `config use-context`) so multiple identities coexist;
resolution is flag > env > current context.

**Catalog and role/group browse.** `folders list`, `assets list`, `roles list`,
and `groups list` all take an optional positional `parent` argument (a DNS-style
path or UUID; omit for the root/global view) and an optional `--cascade` flag:

```
jumpgate assets list                      # direct root-level assets only (usually none)
jumpgate assets list db.prod              # direct assets inside db.prod
jumpgate assets list --cascade            # all visible assets across the full tree
jumpgate assets list db.prod --cascade    # all visible assets inside db.prod's subtree

jumpgate roles list                       # global (folder-less) roles only
jumpgate roles list team.demo             # roles homed directly in team.demo
jumpgate roles list team.demo --cascade   # all visible roles in the team.demo subtree

jumpgate groups list                      # global (folder-less) groups only
jumpgate groups list team.demo --cascade  # all visible groups in the team.demo subtree
```

All four commands are *visibility-filtered* (not cap-gated): a capless caller
gets an empty list; browsing a parent path the caller cannot see returns `NotFound`.
Without `--cascade`, only **direct children** of `parent` are returned — folder-homed
roles and groups are not visible at the root browse unless `--cascade` is used.
Lists are navigation-only (id, name, path); call `assets get <path>` or use the
`Get*Access` detail RPCs to retrieve per-node capabilities. All list verbs page via
an opaque `page_token` cursor returned in `next_page_token`; the CLI handles
pagination automatically.

Admin commands accept asset and folder **paths** everywhere (e.g. `bindings create
--asset password-box.demo`), resolved server-side by `ResolveAsset` /
`ResolveFolder`. Resolution is **capability-aware**: a caller holding the read
capability resolves any object by path; otherwise a non-visible reference returns
`NotFound`. Request policies are addressable as **`<name>@<asset-path>`** via
`ResolvePolicy`, so `policies add-subject approve-deploy@demo-box.demo` works
without capturing an id from a prior create.

## How a session flows

1. **`CreateSession(user, asset)`** — warden re-evaluates the held closure for the
   caller on the asset, and if they are entitled, mints a **PASETO v4.public**
   admission token (Ed25519), short-lived, bound to the client's ephemeral key
   fingerprint (`cnf`) and carrying the session id, user, asset, and protocol. The
   signing key is DB-backed and sealed at rest.
2. **Gateway** verifies the token offline, picks a worker, and tunnels the
   connection to it over mesh mTLS.
3. **`SetupSession`** (worker → warden, over the mesh) re-verifies the token and
   the client-key binding, **re-checks authorization**, writes the **`live_sessions`**
   ledger row and the audit event in one transaction, then mints the target-hop
   credential via the [CredentialBroker](#vault--credentialbroker) — so a credential
   is never issued for a session that was not just re-authorized. warden derives the
   authoritative `worker_id` from the worker's mesh-cert SPIFFE SAN (a worker cannot
   assert an identity it was not issued).
4. **Worker** injects the credential, opens the target hop, records the session,
   and proxies bytes until either side closes or warden signals teardown.

## Access model

Relationship-based (ReBAC), resolved with recursive SQL CTEs over Postgres —
nested-group membership, an explicit role-rewrite folder cascade, and the
Active/Requestable/Invisible visibility tiers. The model separates *what a role
means* (a bundle of capabilities) from *who holds it* (a standing RoleBinding),
modeled on Kubernetes RBAC. Folder cascade of standing access is **explicit**: a
role reaches a folder's descendants only if it declares a `parent` role-rewrite
rule — the same `HoldsRole` predicate backs standing access *and* a request
policy's requester/approver checks.

**Discoverability is a permission.** Against any asset a user is *Active* (holds a
role now), *Requestable* (eligible to request ≥1 role via a policy), or *Invisible*
(existence undisclosed → `NotFound`, never `403`). See
[access-model.md](access-model.md) for the full treatment.

## Just-in-time access & escalation

One request engine, two timings:

- **Pre-session (live)** — request a role before connecting; the injected
  credential carries the privilege. This is what **SSH** uses. Inline TTY gating is
  deliberately avoided — parsing commands from an interactive shell is not a robust
  enforcement boundary.
- **Inline (planned)** — during a live session a specific action pauses pending
  approval, then auto-resumes. This is how **Postgres** will work: `pg-proxy`
  classifies each statement to a privilege tier (`readonly`/`readwrite`/`ddl`), and
  a statement above the current tier offers *approve once* or *elevate to tier X for
  N minutes* (a session-scoped, time-boxed step-up enforced at the DB via
  `SET ROLE`).

Both timings mint the **same primitive**: a time-boxed `access_grants` row (a role
for a user at a scope, with an expiry). It joins the authorizer's held closure
exactly like a standing binding and stops conferring the instant it expires or is
revoked; it never mutates admin config. A grant confers **access, not governance**:
the requester/approver predicates resolve standing-only, so a JIT-granted role can
never be used to request or approve further access. The request → approve → grant
workflow, N-of-M approval, duration clamping, and revocation are detailed in
[access-model.md](access-model.md#approval--who-signs-off-and-how-a-request-activates).

## Vault / CredentialBroker

The vault is the boundary that turns "this user is authorized" into "here is the
short-lived credential to reach the target". It is wired into every live session:
`SetupSession` calls the broker to mint the target-hop credential after
re-authorizing the session.

### Envelope encryption — the `secrets` package

All CA private keys, stored secrets, and the session-signing key are
**envelope-encrypted at rest**:

- A **master KEK** comes from config `VAULT_MASTER_KEY` (base64 **32-byte** key,
  not a passphrase), built into a `secrets.Sealer` at startup. If the key is
  **unset**, the vault is **disabled** (boot + a `slog.Warn`; sealing write paths
  fail closed); a **malformed** key is **fatal**.
- Each secret gets a fresh random **256-bit DEK** — `ct = AES-256-GCM(plaintext,
  DEK)`; the DEK is then **wrapped** by the KEK. `Seal` serializes
  `{version, wrapped_dek, ct}` into one `bytea`; `Open` reverses it. GCM gives
  tamper detection — a wrong KEK or a flipped byte fails `Open` (fail-closed).
- **KMS-ready:** only the DEK-wrap step is the KMS seam; master-key rotation
  re-wraps DEKs only, never the ciphertexts.

Plaintext never touches the DB unsealed, and sealed bytes are **never** returned
via the API. See [security.md](security.md#secrets-at-rest).

### Certificate authorities — the `ca` package

CA private material is sealed into `ca_keys` (at most one **active** per kind),
initialized via `VaultService`:

- **SSH user CA** (ed25519) — `public_material` is the `authorized_keys` CA line
  hosts add to `TrustedUserCAKeys` to trust warden-minted user certs.
- **Mesh CA** (ECDSA P-256, self-signed) — roots the internal mTLS mesh. warden
  signs component CSRs into leaf certs carrying a `spiffe://jumpgate/<role>/<id>`
  URI SAN; it trusts the caller-asserted SPIFFE id from the RPC, never the CSR's
  own SANs.
- **X.509 client CA** (ECDSA P-256) — built and tested for a future
  certificate-based target hop (Postgres/k8s); not yet reachable via any asset
  kind.

### The broker + providers

`CredentialBroker.Issue(ctx, userID, assetID, params)` — where the params carry the
requested login, the public key to certify for the target hop (the worker's
per-session key **Kw**, for the `ca` kind), and the credential's validity — is an
**internal Go seam, not an RPC**. SSH auth is **per-login**: the
broker loads the asset's `ssh_asset_login` rows, enforces the `ssh:login:<Login>`
capability for the requested login **uniformly, for every kind**, and runs the
provider for that login's `kind`:

- **ca** — signs the target-hop public key into an SSH **user cert** with
  **host-scoped principals** (`[<login>@<asset-path>, <login>@<asset-id>]`, e.g.
  `deploy@pg-primary.db.prod`), `ValidBefore = ValidUntil`. The path form is the
  stable identifier automation writes into the target's `AuthorizedPrincipalsFile`;
  the id form provides rename safety. The cert binds the login to a **specific
  asset**; the worker requires every principal to be of the form `<login>@<scope>`,
  and the target enforces the binding via its `AuthorizedPrincipalsFile`.
- **password** — opens the login's linked `asset_secret` and returns the plain
  password bytes.
- **key** — opens the login's linked `asset_secret` and returns the OpenSSH
  private-key PEM.

A stored secret is **plain** (just the password or key); the login and kind live
in the `ssh_asset_login` row, and a login's `secret_id` is bound by a composite FK
to a secret **of the same asset**, so one asset's login cannot reference another
asset's secret. `ValidUntil`/`KeyID` are supplied by the caller: `SetupSession`
passes the granting authorization's remaining lifetime, so a credential never
outlives the access behind it. Every successful `Issue` appends a
**`credential.issued`** audit event.

### Capability-driven SSH principals

The broker is the enforcement point for **which OS accounts a user may log in as**.
It does not trust the asset's login rows wholesale — the requested login must
survive the intersection with the user's live capabilities before any credential
is minted:

```
allow(Login) ⇔ Login ∈ {the asset's ssh_asset_login rows}
             ∧ authz.Check(user, asset, "ssh:login:" + Login)
```

`Check` is the same glob-aware, grant-aware authorizer used everywhere: a role
holding `ssh:login:*` matches every configured login; `ssh:login:root` matches
just `root`; the capability may be held via a standing binding **or** an active JIT
grant. An **empty** intersection is **refused** (no cert, no audit); the `ca` layer
**independently** refuses to sign a principal-less certificate as
defense-in-depth. So the minted cert authorizes **exactly** the logins the user is
entitled to — no static host login. See
[access-model.md](access-model.md#ssh-access--os-logins-are-capabilities).

### Admin surface

`VaultService` is capability-guarded: `InitCA` / `GetCAPublic`, the mesh CA
(`InitMeshCA` / `IssueMeshCert`), `InitSessionKey`, and asset-secret
`Set`/`Delete`/`List` (**metadata only — id/name/created_at, never the value**).
The SSH asset's connection config (per-login `{login, kind, secret_id}` plus target
address and host key) lives on **`CatalogService`**, which owns the asset:
`CreateAsset` takes inline typed config, `GetAsset` returns it, `UpdateAssetConfig`
upserts it, and the `jumpgate assets ssh` CLI drives it. A `password`/`key` login
seals its secret via `VaultService.SetAssetSecret` and links it by `secret_id`;
the sealed bytes stay in the vault.

## Continuous revocation — live-session teardown

**Authorization is continuous, not connect-time only.** A session is authorized for
its whole lifetime, not just at the handshake. When the authorization a live
session depends on is revoked, that session is **terminated**. "Zero standing
access" is only true if losing access ends access *now*.

warden is the source of truth, so it **signals** teardown. Every live session is
recorded in the durable **`live_sessions`** ledger, keyed to the grant and/or
standing authorization it relies on. Two mechanisms drive re-evaluation, both
level-triggered so a lost signal self-heals:

- **push** — a change (a grant reaped or revoked; a role binding, group membership,
  or role-rewrite rule removed; a capability dropped; a user deactivated) fires a
  Postgres `authz_changed` notification. warden re-evaluates the held closure for
  the affected sessions and, for any whose authorization no longer holds, requests
  teardown from the owning worker over its control stream.
- **pull** — a periodic **sweep** (debounced) re-checks live sessions as a
  backstop. Re-evaluation is **ownership-partitioned**: each warden replica sweeps
  only the sessions of workers connected to it, so every session is evaluated
  exactly once fleet-wide. An **orphan GC**, driven off a worker-presence
  heartbeat, reconciles sessions whose owning worker is unreachable and stuck
  teardowns.

**Revocation sources** that trigger teardown of any dependent live session:

| Source | Change |
|---|---|
| JIT grant | expires (the reaper) or is revoked (manual · self · approver · deactivation) |
| Standing `role_binding` | deleted |
| `role_grants` rewrite rule | changed so it no longer confers the role |
| Group membership | a `group_memberships` row removed |
| Role capability | removed from the role |
| User | deactivated |

Every forced termination is a `session.terminated` audit event in the hash-chained
log, alongside the revocation that caused it.

## Audit & recording

Every security-relevant event is written to an append-only, **hash-chained** audit
log (`entry_hash = sha256(prev_hash ‖ canonical(entry))`) so tampering breaks the
chain and is detectable (`Verify`). The JIT workflow emits
`access_request.created`/`.approved`/`.denied`/`.cancelled` and
`access_grant.activated`/`.revoked`/`.expired`; the vault emits `credential.issued`;
the data plane emits `session.terminated` and `recording.completed`/`.failed` and
`recording.accessed`.

Most events are written through a **transactional outbox**: each service `Enqueue`s
its event into `audit_outbox` inside the same domain transaction (atomic with the
state change), and a background drainer chains outbox rows into the hash-linked log
— closing the post-commit crash window (see
[security.md](security.md#tamper-evident-audit)). The vault's `credential.issued`
is a genuinely post-fact append (no domain tx to join) and uses direct `Append`.

**SSH session recording.** SSH sessions are recorded by default at the terminating
worker in **asciicast v2** (both directions of I/O plus terminal resizes, with
timing — replayable with `asciinema play`). Recording is **mandatory unless** the
subject holds `ssh:record:exempt` on the asset; warden decides this at session
setup and the worker **fails closed** — if a required recording cannot be
established, or a mid-session write fails, the session is refused or torn down. The
worker streams the recording directly to S3-compatible object storage via multipart
upload (parts flushed as the session runs, so a crash loses at most the last part),
maintaining a rolling SHA-256, and signs its own requests with a lightweight S3
client (no heavyweight SDK). On completion it reports `{object_key, size, sha256,
status}` to warden, which persists a `session_recordings` row. Admins retrieve a
recording through `RecordingService` (list/get and a short-lived **presigned GET
URL**, audited as `recording.accessed`). The object key is protocol-partitioned
(`recordings/ssh/<date>/<session_id>.cast`) so one bucket can serve other protocols
later. Postgres statement-log recording, other protocols, a web replay player, and
SIEM export are planned.

## Running on Kubernetes (kind)

The whole stack runs on a local [kind](https://kind.sigs.k8s.io/) cluster from a
Helm chart, so the control plane, gateway, and an ssh-proxy worker can be exercised
end to end without hand-wiring certificates or processes.

- **Chart — `deploy/helm/jumpgate`.** Renders warden, the gateway, and one
  ssh-proxy worker, plus their Services, Secrets, and mesh Certificates. warden's
  user API and the gateway's external listener are exposed as fixed NodePorts,
  which the kind cluster (`test/env/cluster.yaml`) forwards to `localhost:8080`
  (warden) and `localhost:8443` (gateway) so the host CLI reaches them directly.
- **Mesh certificates via cert-manager.** The chart provisions a cert-manager
  `Issuer` rooted at warden's mesh CA and issues each mesh peer a certificate with
  its `spiffe://jumpgate/<role>/<id>` URI SAN — the same identity the gateway pins
  when it dials. The gateway's **external** TLS is a separate cert whose CA the CLI
  must trust; `make kind-demo` exports it to `./jumpgate-mesh-ca.pem`.
- **`warden-bootstrap` pre-install Job.** A Helm pre-install hook initializes the
  one-time cluster state the RPCs cannot bootstrap themselves: it seals the vault
  master key, mints warden's mesh CA and session-signing key, creates the bootstrap
  admin, and publishes the SSH user CA's public key as a Secret the ssh test
  workload mounts.
- **Toggleable in-cluster dependencies.** `postgres.enabled` runs an in-cluster
  Postgres for warden's data (set it false and point `warden.databaseUrl` at an
  external database); `silo.enabled` runs an in-cluster S3-compatible object store
  for recordings (disable it to use any external S3 endpoint).
- **Independent sshd test workload — `test/env/testworkload`.** A minimal sshd
  Deployment that trusts the bootstrap SSH user CA. It is a *target*, not part of
  jumpgate, and is applied separately so the chart stays deployment-agnostic.
- **Make targets.** `make kind-up` creates the cluster, installs cert-manager and
  the chart, and deploys the sshd workload; `make kind-demo` also exports the mesh
  CA and prints the CLI setup; `make kind-e2e` runs the Go e2e suite (`test/e2e`)
  against the live stack — a three-actor cross-approval scenario driving the real
  CLI (an admin onboards an SSH asset and a request policy; two users request and
  approve each other's access; one connects and runs a command; an admin auditor
  downloads the recording and confirms it captured the session).

## Key technology choices

See [decisions.md](decisions.md) for the rationale behind Go + Rust, the two-tier
data plane, the agentless posture, the recursive-CTE authorizer, PASETO, and
envelope-encrypted secrets.
