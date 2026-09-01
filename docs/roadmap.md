# Roadmap

What is built and what is planned. jumpgate is delivered as a sequence of milestones,
each producing working, testable software: the JIT access core, then SSH, Postgres,
and Kubernetes access, then the web console. Later product areas follow.

## Milestones

| Milestone | Scope | Status |
|-----------|-------|--------|
| M1 | Foundation and scaffolding — Nix devshell, Go and Rust workspaces, protobuf codegen, health binaries, CI | ✅ Done |
| M2 | Access-model core — users/groups/folders/assets, custom Role plus RoleBinding, recursive-CTE authorizer, visibility tiers, catalog and discovery | ✅ Done |
| M3 | JIT plus vault plus audit — request policies, N-of-M approval engine, time-boxed grants plus reaper, envelope-encrypted credential vault plus CAs, hash-chained audit | ✅ Done |
| M4 | SSH data plane — Rust gateway, ssh-proxy worker, `jumpgate connect`, live credential injection, continuous-revocation teardown, session recording, kind plus Helm environment | ✅ Done |
| M5 | Postgres access — pg-proxy worker, `mtls` and `password` logins, loopback CLI proxy, statement-log recording | ✅ Done |
| M6 | Kubernetes access — dial-out in-cluster agent plus broker, exec-plugin and kubeconfig, group-to-RBAC impersonation, API-audit recording | ✅ Done |
| M7 | Web console — embedded SPA: admin, approvals, in-browser terminal, recording playback, asset authoring | ✅ Done |
| M8 | Inline step-up and enterprise readiness — Postgres per-statement step-up, OIDC/SAML SSO, SCIM sync, production deploy hardening | ⬜ Planned |

## What's built

Control plane (Go, warden). ConnectRPC API (Connect, gRPC, and gRPC-Web on one
handler) plus a separate mutually-authenticated mesh listener. Postgres via sqlc and
pgx with embedded goose migrations. Opaque, hashed, revocable bearer tokens (argon2id
passwords). Capability-only management authz — no admin flag; the bootstrap admin holds
`**` via a global binding. Existence-hiding (`CodeNotFound`) throughout.

Access model. Nested groups; folder-scoped roles and folder-governed groups; an
explicit ReBAC-light role-rewrite engine (`role_grants` plus `HoldsRole`) resolved with
recursive SQL CTEs; standing-only bindings (folder, asset, global); the Active /
Requestable / Invisible visibility tiers; fine-grained management capabilities with a
folder cascade and a no-escalation subset rule; capabilities stored decomposed in
`role_capabilities` and matched by an SQL predicate pinned equal to the Go glob.

JIT access. Request policies make a role requestable per (role, scope) and carry the
requester and approver sets; request → N-of-M approve (self-service at
`required_approvals=0`) → a time-boxed `access_grants` row that joins the held closure
and expires (reaper). Grants confer access, not governance. Revocation by expiry,
manual revoke (oversight, self, approver), or deactivation.

Vault and credentials. Envelope-encrypted secrets at rest (per-secret DEK wrapped by a
master KEK, KMS-ready); SSH user CA, mesh CA, and an in-use X.509 client CA. The
`CredentialBroker` mints short-lived, capability-scoped credentials, wired into every
live session: per-login SSH auth (`ca` / `password` / `key`) with host-scoped cert
principals, and per-role Postgres auth (`mtls` client cert / `password`). Kubernetes
agents get a mesh identity through single-use enrollment tokens.

SSH access. A Rust gateway (external TLS → HTTP CONNECT → offline PASETO verify →
least-loaded worker → mesh mTLS with SPIFFE pinning → bidirectional pump); an ssh-proxy
worker (russh, two-hop key-separated credential injection, real teardown). SSH sessions
are recorded by default (asciicast v2, fail-closed, streamed to object storage,
presigned-GET retrieval).

Postgres access. A Go pg-proxy worker fronts a Postgres target: `CreatePostgresSession`
mints a bearer admission token, and `jumpgate connect <role>@<pg>` binds a loopback
proxy for any libpq client. Logins are `db:login:<role>`-gated and minted as a
short-lived X.509 client cert or the sealed password; the target is dialed over TLS
with no plaintext downgrade. Every session is recorded as a `pgwire-timeline-v1`
statement log (fail-closed, bind values and result rows redacted).

Kubernetes access. A Go agent runs inside the target cluster and dials out to a Go
broker, serving a reverse HTTP/2 tunnel; the stateless gateway routes by the token's
`broker_id`. Access is gated by concrete `k8s:group:<name>` capabilities, which the
broker projects as impersonation headers (email plus groups) — the cluster's own RBAC
decides what each group may do, and wildcards grant nothing. Each `kubectl` invocation
is recorded as a `k8s-audit-v1` API-request log. `jumpgate k8s auth` is an exec-plugin
and `jumpgate k8s kubeconfig` wires `kubectl` through jumpgate.

Web console. A React SPA embedded in the warden binary (behind the `embedui` tag)
serves the access loop same-origin over cookie-session auth: an Overview dashboard, a
catalog browser with SSH/Postgres/Kubernetes asset authoring, My Access, an approver
inbox, a directory, access-control authoring, recording playback for all three formats,
and an in-browser SSH terminal. See [development.md](development.md#web-ui).

Client and environment. The `jumpgate` CLI drives the whole surface (connect, admin,
access requests, recordings, `k8s`) with kubectl-style contexts and DNS-style asset
paths. The stack runs on a local kind cluster from a Helm chart with cert-manager mesh
certs and a bootstrap Job; `make e2e-cluster` runs a Go e2e suite that drives the real
CLI (and `kubectl`) through the SSH, Postgres, and Kubernetes paths. Narrated
walkthroughs follow the same flows (`docs/demo/walkthrough.md`, `walkthrough-ui.md`).

Code quality. The authorization semantics are a single source of truth as inlinable
PostgreSQL SQL functions (`authz_*` plus the `active_access_grants` view) consumed via
static sqlc, guarded against Go-side re-implementation by a grep test. warden is
organized as vertical-slice domain modules (`internal/<domain>/{service.go,handler.go}`)
over shared transport leaves (`apiguard` / `apierr` / `apipage`), with `internal/rpc`
reduced to wiring and no public library API. Cross-domain cleanup runs off DB FK
cascade.

## Later areas

| Area | Adds |
|---|---|
| Inline step-up | Postgres per-statement approval and time-boxed `SET ROLE` tiers |
| Enterprise identity | OIDC/SAML SSO, SCIM group sync |
| RDP plus more databases | IronRDP (Rust), MySQL/Mongo, browser RDP |
| k8s operator / CRDs | Declarative assets, roles, and policies via a Go controller |
| Generic HTTP/API plus inline DLP | Web-app proxy, PII masking, command/query blocking, ChatOps approvals, SIEM export |

## Known deferrals

Carried forward deliberately, to be addressed when their area opens:

- Target SSH host-key pinning — plumbed (`ssh_asset_config.host_public_key`) but not
  yet enforced.
- Inline Postgres per-statement step-up — the `db:read` / `db:write` / `db:ddl` tiers
  are defined for the model; per-statement `SET ROLE` enforcement is not built.
- In-browser SQL console — Postgres is reachable through the loopback CLI proxy; a
  clientless browser SQL console is not built.
- Kubernetes agent certificate auto-renewal — the 24-hour agent cert is not
  auto-renewed; a long-lived agent re-enrolls when its pod is recreated.
- Kubernetes tunnel-advertisement ownership validation and a production gateway
  serving-cert DNS SAN — see [security.md](security.md#kubernetes-agent-trust).
- Orphaned multipart-upload cleanup — left to an object-store lifecycle rule.
- SIEM export of the audit log and recordings — later.
