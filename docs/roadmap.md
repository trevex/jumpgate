# Roadmap

The MVP (Sub-project #1: **SSH + Postgres + JIT core**) is built as a sequence of
milestones, each producing working, testable software. Later product sub-projects
follow the MVP.

## MVP milestones

| Milestone | Scope | Status |
|-----------|-------|--------|
| **M1** | Foundation & scaffolding — Nix devshell, Go+Rust workspaces, protobuf codegen, warden (control plane) + gateway health binaries, CI | ✅ Done |
| **M2** | Access-model core — users/groups/folders/assets, custom Role + RoleBinding over OpenFGA, visibility tiers, catalog/CRUD REST | ✅ Done (data, authorizer, ConnectRPC, auth, identity, catalog/visibility) |
| **M3** | JIT + vault + audit — access requests, approval engine, time-boxed grants + reaper, credential vault, hash-chained audit | ✅ Done (M3a audit + M3-roles explicit ReBAC-light role model + M3b approval policy + M3c JIT request→approve→grant→reaper + **M3d CredentialBroker/vault + SSH/x509 CAs**) |
| **M4** | Gateway + ssh-proxy + CLI — worker registry, session routing/LB, `jumpgate connect <ssh>` end-to-end with **live credential injection** (the worker calling the broker's `Issue`) + the real **`GrantTerminator`** session-kill path + recording | ⬜ |
| **M5** | pg-proxy + inline step-up — Postgres access, per-statement approval, tiered `SET ROLE` step-up | ⬜ |
| **M6** | Web UI — embedded SPA, admin console, approvals, xterm.js terminal, web SQL console | ⬜ |
| **M7** | Deploy — Helm chart + docker-compose packaging | ⬜ |

### M3 sub-milestones

| Sub | Scope | Status |
|-----|-------|--------|
| **M3a** | Hash-chained tamper-evident audit log (Append/Verify) | ✅ Done |
| **M3-roles** | Explicit ReBAC-light role model — `role_grants`, `HoldsRole`, rewired Authorizer + approver-role, admin API + `ExplainRole` | ✅ Done |
| **M3b** | Approval/request policy model — `request_policies` + subjects, most-specific resolution, requester/approver predicates, `ResolveApproval` | ✅ Done |
| **M3c** | JIT runtime — `RequestAccess`/approve/deny/cancel (N-of-M; self-service at `required_approvals=0`), time-boxed `access_grants` joining the held closure (grants≠governance), duration clamp, expiry **reaper**, manual/self/approver/deactivation revocation, teardown seam (no-op), full audit events | ✅ Done |
| **M3d** | CredentialBroker/vault — envelope crypto (per-secret DEK + master KEK), SSH user CA + X.509 client CA (sealed at rest), the `CredentialBroker` seam with **capability-driven SSH principals** + stored-secret provider, `VaultService` admin API, `credential.issued` audit. **Completes M3.** | ✅ Done |

**M3 is complete.** The x509 and stored-secret providers are built + tested; the
`postgres`/`k8s` typed configs and **live credential injection** (the worker
calling the broker's `Issue`) land in **M4/M5**.

**Post-M3 hardening pass ✅.** Before M4: a **held-closure drift-guard** test that
locks the duplicated recursive-CTE copies in sync, and a **transactional audit
outbox** — the JIT services + reaper enqueue each event inside their domain tx and
a background drainer chains it into the hash-linked log, closing the post-commit
crash window. Deferred to later milestones: CA rotation and the eligibility-change
grant cascade.

**M4a — data-plane spine ✅.** The spine shipped: session-token **minting**
(`CreateSession`), the worker ↔ warden `dataplane/v1` contract (`SetupSession` +
`WorkerStream`), the durable **`live_sessions`** ledger, and the real **grant-keyed
`GrantTerminator`** (closure re-eval + **`LISTEN/NOTIFY`** to the owning worker
stream). The signing key is initialized via the admin `InitSessionKey` RPC (loaded
once at boot — restart warden after init to enable `CreateSession`/`SetupSession`).
Remaining: **M4c** ssh-proxy worker + `jumpgate connect` CLI, **M4d** eligibility
cascade + pull-sweep + orphan-GC, **M4e** recording.

**M4b — Rust gateway + mesh mTLS ✅.** The gateway ships: external TLS →
**HTTP CONNECT** (token in `Authorization: Bearer`) → **offline PASETO verify**
(sig/exp; reads `proto`) → least-loaded worker pick → **mTLS dial + CONNECT** →
`copy_bidirectional` pinned byte pump (teardown propagates as EOF; the gateway is
teardown-unaware). warden grew a **warden-rooted `mesh` CA** (`InitMeshCA` +
`IssueMeshCert` CSR-signing + the `warden-meshcert` CLI), a **second mTLS listener**
serving `Dataplane`+`Gateway`, and a **`GatewayService`** (`WatchWorkers` roster +
`GetSessionVerificationKey`). The **M4a self-asserted-`worker_id` gap is CLOSED**:
warden derives the authoritative `worker_id` from the mTLS peer-cert URI SAN
(`spiffe://jumpgate/<role>/<id>`), and the gateway pins each peer's SPIFFE identity
(chain-to-mesh-CA **and** URI-SAN==expected) on both the worker and warden dials.
warden's mesh cert must be minted with the SPIFFE id the gateway pins — canonical
default `spiffe://jumpgate/warden/warden` (override via `WARDEN_MESH_SPIFFE`; mint
with `warden-meshcert -spiffe spiffe://jumpgate/warden/warden`).
Go↔Rust PASETO interop is locked by a fixture test. Deferred: boot-time cert
auto-enrollment, global multi-replica LB, k8s discovery, a real public external cert.

**M4c — ssh-proxy worker + `jumpgate connect` CLI ✅.** `jumpgate connect
<login>@<asset>` works end-to-end against a real SSH host. The **ssh-proxy worker**
(Rust/russh) terminates the client's SSH, drives session-setup from its
publickey-auth callback, and proxies to the target with an injected certificate;
credential injection is **two-hop key-separated** — the client proves its ephemeral
key **Kc** (the token's binding) to the worker, and the control plane certifies a
fresh worker key **Kw** for the target hop, so the worker (not the client) holds the
key that reaches the target. Teardown is now real for SSH (a control-plane signal
force-closes the live session; the worker reports its end). The **`jumpgate` CLI**
(Go) does login → session → gateway `CONNECT` tunnel → interactive `x/crypto/ssh`
pty. The gateway's mesh mTLS/`CONNECT` code was extracted into a shared
**`jumpgate-mesh`** crate. A full-stack test (opt-in `make e2e-ssh`) drives the real
warden + gateway + worker binaries end-to-end. Deferred: session recording,
target host-key pinning enforcement (plumbed but not enforced), scp/port-forwarding,
and a containerized (compose/kind) e2e environment.

**M4d — eligibility-change cascade + pull-sweep + orphan-GC ✅.** Teardown now
fires for **standing** authorization changes, not just grants: deleting a
`role_binding`, removing a `group_memberships` row, changing a `role_grants`
rewrite rule, dropping a role capability, or deactivating a user re-evaluates every
dependent live session and force-closes those no longer permitted. Detection is
**push + pull**: database change notifications drive near-instant re-evaluation, and
a periodic **sweep** (debounced) is the backstop. Re-evaluation is
**ownership-partitioned** — each replica sweeps only the sessions of workers
connected to it, so every session is evaluated exactly once fleet-wide. An
**orphan GC** reconciles sessions whose owning worker is unreachable and stuck
teardowns, driven off a worker-presence heartbeat. Proven end-to-end by the
full-stack test: a held-open SSH session is force-closed within seconds of its
standing binding being deleted through the admin API, with a matching
`session.terminated` audit event.

**M4e — session recording ✅.** SSH sessions are recorded by default at the
terminating worker in **asciicast v2** (input + output + resize, with timing),
streamed directly to S3-compatible object storage via multipart upload (parts
flushed as the session runs) with a rolling SHA-256. Recording is **fail-closed and
mandatory** unless the subject holds `ssh:record:exempt` on the asset: warden
decides at setup and the worker refuses/tears down a required session it cannot
record. The worker signs its own S3 requests (`rusty-s3` + a ring-backed rustls HTTP
client — no heavyweight SDK), reports `{object_key, size, sha256, status}` to warden
on completion, and warden persists a `session_recordings` row + audits
`recording.completed`/`.failed` into the hash-chained log. Admins retrieve via the
`RecordingService` (presigned GET, audited). Proven end-to-end against a real
S3-compatible store: a recorded session yields a valid, hash-matched asciicast; an
exempt session yields none; a store failure refuses the session. Deferred: aborting
orphaned multipart uploads is left to an object-store lifecycle rule (incomplete
multipart expiration); other protocols and a web replay player are later.

**Containerized environment (kind + Helm) ✅.** A local [kind](https://kind.sigs.k8s.io/)
environment brings the whole stack up from a Helm chart (`deploy/helm/jumpgate`):
warden, the gateway, and an ssh-proxy worker, with cert-manager-issued mesh certs
under warden's CA, a `warden-bootstrap` pre-install Job (vault master key, mesh CA,
session-signing key, bootstrap admin, SSH user CA), toggleable in-cluster
Postgres + object store, and an independent sshd test workload. warden and the
gateway are forwarded to fixed host ports so the CLI reaches them directly. Driven
by `make kind-up` / `kind-demo` / `kind-e2e`. The Go e2e suite (`test/e2e`) drives the
real CLI through a three-actor cross-approval scenario against the live stack: an admin
onboards an SSH asset and a request policy, two users request and approve each other's
access, one connects and runs a command, and the admin auditor downloads the recording
and confirms it captured the session. A narrated walkthrough (`docs/demo/walkthrough.md`)
follows the same command sequence for a live demo. This also bootstraps M7 packaging.

## Beyond the MVP (later product sub-projects)

| # | Sub-project | Adds |
|---|-------------|------|
| 2 | Enterprise identity | OIDC/SAML SSO, SCIM group sync |
| 3 | RDP + more databases | IronRDP (Rust), MySQL/Mongo, browser RDP |
| 4 | Kubernetes access | k8s API proxy + impersonation + audit |
| 5 | k8s operator / CRDs | Declarative assets/roles/policies via a Go controller |
| 6 | Generic HTTP/API + inline DLP | Web-app proxy, PII masking, command/query blocking, ChatOps approvals, SIEM export |

## Carried-forward items (address as their milestone opens)

These were surfaced during M1 review and are intentionally deferred:

- **Graceful shutdown** in both binaries (Go `http.Server.Shutdown` + signal; Rust
  `tokio::signal`) — needed **before M2** opens persistent DB/gRPC connections.
- **CI Nix caching** (e.g. magic-nix-cache / Cachix) — before CI runtime becomes painful.
- **Explicit `.golangci.yml`** — pin the linter set before real app code lands.
- **Second Go module (`cli`) coverage** in the Makefile's Go targets (M4).
