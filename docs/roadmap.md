# Roadmap

What is built and what is planned. The first product — **SSH + Postgres + JIT
core** — is delivered as a sequence of milestones, each producing working, testable
software; later product areas follow.

## Milestones

| Milestone | Scope | Status |
|-----------|-------|--------|
| **M1** | Foundation & scaffolding — Nix devshell, Go + Rust workspaces, protobuf codegen, health binaries, CI | ✅ Done |
| **M2** | Access-model core — users/groups/folders/assets, custom Role + RoleBinding, recursive-CTE authorizer, visibility tiers, catalog & discovery | ✅ Done |
| **M3** | JIT + vault + audit — request policies, N-of-M approval engine, time-boxed grants + reaper, envelope-encrypted credential vault + CAs, hash-chained audit | ✅ Done |
| **M4** | Data plane — Rust gateway, ssh-proxy worker, `jumpgate connect` CLI, live credential injection, continuous-revocation teardown, session recording, kind + Helm environment | ✅ Done |
| **M5** | pg-proxy + inline step-up — Postgres access, per-statement approval, tiered `SET ROLE` step-up | ⬜ Planned |
| **M6** | Web UI — embedded SPA: admin console, approvals, terminal, SQL console | ⬜ Planned |
| **M7** | Deploy — production packaging beyond the kind/Helm dev environment | ⬜ Planned |

## What's built (M1–M4)

**Control plane (Go, warden).** ConnectRPC API (Connect + gRPC + gRPC-Web on one
handler) plus a separate mutually-authenticated mesh listener. Postgres via sqlc +
pgx with embedded goose migrations. Opaque, hashed, revocable bearer tokens
(argon2id passwords). Capability-only management authz — no admin flag; the
bootstrap admin holds `**` via a global binding. Existence-hiding (`CodeNotFound`)
throughout.

**Access model.** Nested groups; folder-scoped roles and folder-governed groups; an
explicit ReBAC-light role-rewrite engine (`role_grants` + `HoldsRole`) resolved with
recursive SQL CTEs; standing-only bindings (folder / asset / global); the
Active / Requestable / Invisible visibility tiers; fine-grained management
capabilities with a folder cascade and a no-escalation subset rule.

**JIT access.** Request policies make a role requestable per (role, scope) and carry
the requester/approver sets; request → N-of-M approve (self-service at
`required_approvals=0`) → a time-boxed `access_grants` row that joins the held
closure and expires (reaper). Grants confer access, not governance. Revocation by
expiry, manual revoke (oversight / self / approver), or deactivation.

**Vault & credentials.** Envelope-encrypted secrets at rest (per-secret DEK wrapped
by a master KEK, KMS-ready); SSH user CA, mesh CA, and an X.509 client CA (built for
future use). The `CredentialBroker` mints short-lived, capability-scoped
credentials, wired into every live session; per-login SSH auth (`ca` / `password` /
`key`) with host-scoped cert principals; uniform `ssh:login:<login>` enforcement.

**Data plane.** A Rust gateway (external TLS → HTTP CONNECT + offline PASETO verify →
least-loaded worker → mesh mTLS with SPIFFE pinning → bidirectional pump); an
ssh-proxy worker (russh, two-hop key-separated credential injection, real teardown);
mesh mTLS rooted at warden's CA with cert-SAN-derived worker identity; PASETO
v4.public admission tokens bound to the client key. Continuous revocation tears down
live sessions on any authorization change (grant, binding, membership, rewrite,
capability, deactivation) via push (`authz_changed` notify) + a pull sweep, with
ownership partitioning and orphan GC. SSH sessions are recorded by default
(asciicast v2, fail-closed, streamed to object storage, presigned-GET retrieval).

**Client & environment.** The `jumpgate` CLI drives the whole surface (connect,
admin, access requests, recordings) with kubectl-style contexts and DNS-style asset
paths. The stack runs on a local kind cluster from a Helm chart with
cert-manager-issued mesh certs and a bootstrap Job; `make e2e-cluster` runs a Go e2e
suite that drives the real CLI through a three-actor cross-approval scenario. A
narrated walkthrough (`docs/demo/walkthrough.md`) follows the same flow.

**Code quality.** A structural refactor is complete: the authorization semantics are
a single source of truth as inlinable PostgreSQL SQL functions (`authz_*` + the
`active_access_grants` view) consumed via static sqlc, guarded against Go-side
re-implementation by a grep test; warden is organized as vertical-slice domain
modules (`internal/<domain>/{service.go,handler.go}`) over shared transport leaves
(`apiguard`/`apierr`/`apipage`) with `internal/rpc` reduced to wiring and
`warden/authz` the one public interface; cross-domain cleanup runs off DB FK cascade;
and the test tiers, package boundaries, and durable docs were consolidated to match
(see [testing.md](testing.md) and [development.md](development.md)).

## Beyond the first product (later areas)

| Area | Adds |
|---|---|
| Enterprise identity | OIDC/SAML SSO, SCIM group sync |
| RDP + more databases | IronRDP (Rust), MySQL/Mongo, browser RDP |
| Kubernetes access | k8s API proxy + impersonation + audit |
| k8s operator / CRDs | Declarative assets/roles/policies via a Go controller |
| Generic HTTP/API + inline DLP | Web-app proxy, PII masking, command/query blocking, ChatOps approvals, SIEM export |

## Known deferrals

Carried forward deliberately, to be addressed when their area opens:

- **Target SSH host-key pinning** — plumbed (`ssh_asset_config.host_public_key`) but
  not yet enforced.
- **Postgres/Kubernetes credential kinds** and the X.509 client-cert target hop —
  built in the vault, not yet reachable via an asset kind.
- **Orphaned multipart-upload cleanup** — left to an object-store lifecycle rule.
- **Web replay player** and **Postgres statement-log recording** — later, with their
  protocols.
