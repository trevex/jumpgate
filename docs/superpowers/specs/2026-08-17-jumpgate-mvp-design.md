# jumpgate — MVP Design (Sub-project #1: SSH + Postgres + JIT Core)

- **Status:** Draft for review
- **Date:** 2026-08-17
- **Scope:** This spec covers **only** the first sub-project. The broader product roadmap is listed for context; each later sub-project gets its own spec → plan → implementation cycle.

---

## 1. Vision & positioning

jumpgate is an enterprise-ready Privileged Access Management (PAM) / secure infrastructure access platform — comparable to Teleport, JumpServer, StrongDM, and hoop.dev — that proxies access to Kubernetes, VMs (SSH + RDP), databases, and generic APIs/web services.

**Core bet:** *zero standing access* with **"access when you need it"** — nothing is granted until requested; access is time-boxed, approval-gated, credential-injected, fully recorded, and auto-expiring.

**Primary differentiation:** JIT-first, developer-friendly experience with a permissive open-source core, **with a pinch of enterprise compliance** (tamper-evident audit, session recording, least-privilege/no-enumeration). Secondary future wedges (later sub-projects): inline data-loss protection (DLP), and AI-agent/MCP governance.

**Architecture posture:** an **agentless L7 gateway** (hoop-style) — no software installed on target resources — realized as a **two-tier data plane** so protocols scale independently and each protocol can be implemented in whichever language best fits it.

## 2. Ecosystem decision (context)

Backed by competitive + ecosystem research (see conversation history / research notes):

- **Go** for the control plane, operator (future), API, authorization, SSO (future): canonical Kubernetes operator ecosystem (kubebuilder/controller-runtime), mature ReBAC engines (OpenFGA/SpiceDB), enterprise SSO breadth (crewjam/saml, go-oidc), team velocity/hiring.
- **Rust** for the data plane: best proxy performance/tail-latency and memory safety on the untrusted-input path; uniquely strong for **RDP (IronRDP)** in a future sub-project. MVP Rust surface is small: `russh` (SSH) + `pgwire`/`sqlparser-rs` (Postgres).
- The **two-tier data plane** (gateway + per-protocol workers) preserves the option to write a future worker in Go (e.g., `k8s-proxy` on `client-go`, `mysql-proxy` on Vitess) behind the same Rust gateway.

## 3. Product decomposition (roadmap)

| # | Sub-project | Delivers |
|---|---|---|
| **1 (this spec)** | **SSH + Postgres + JIT core** | Gateway + `ssh-proxy` + `pg-proxy` (Rust), Go control plane, OpenFGA ReBAC with custom roles, local accounts, JIT request→approve→time-boxed grant, Postgres inline per-statement approval + tiered step-up, credential injection, session recording, tamper-evident audit, CLI + browser clients, Helm deploy |
| 2 | Enterprise identity | OIDC/SAML SSO, SCIM group provisioning/sync |
| 3 | RDP + more databases | IronRDP (Rust), MySQL/Mongo workers, browser RDP (Guacamole or Teleport-TDP-style frame streaming) |
| 4 | Kubernetes access | k8s API proxy + impersonation + audit (candidate Go worker) |
| 5 | k8s operator / CRDs | Declarative assets/folders/roles/policies via a Go controller |
| 6 | Generic HTTP/API + inline DLP | Reverse-proxy web apps, PII/PHI masking, command/query blocking, Slack/Teams approvals, SIEM export |

## 4. MVP scope (this spec)

**In:** SSH and Postgres access through the agentless two-tier gateway; custom Role + RoleBinding ReBAC access model with nested groups, folder hierarchies, and permission-gated discoverability; local accounts/groups; JIT access requests with an approval engine (in-app); credential injection from a vault; Postgres inline per-statement approval with time-boxed tiered step-up; SSH pre-session elevation only; session recording; hash-chained tamper-evident audit; CLI + browser clients; Helm/k8s + docker-compose deploy.

**Out (later sub-projects):** OIDC/SAML/SCIM; RDP; k8s access; the operator/CRDs; MySQL/Mongo; inline DLP/command-blocking; SSH inline sudo gating; Slack/Teams approvals; SIEM export; HA/multi-region; host-side PAM/sudo plugin.

## 5. Architecture overview

```
                    ┌──────────────── Go control plane ────────────────┐
                    │ identity · OpenFGA graph · roles/bindings · JIT   │
                    │ grants · vault · approval engine · audit ·        │
                    │ recording metadata · worker-pool registry (k8s)  │
                    └──────▲───────────────▲──────────────────▲────────┘
              token mint / │      gRPC:    │ authz + creds    │ recording/audit
              introspection│  pool roster  │ + approvals      │ events
                    ┌──────┴──────┐        │                  │
   client ────TLS──►│   Gateway   │  (only exposed endpoint; thin, protocol-agnostic,
 (CLI tunnel /      │  (Rust)     │   session-aware load balancer + token validator)
  browser WSS)      └──────┬──────┘
                           │ forwards pinned session stream to a chosen worker
          ┌────────────────┼───────────────────┐
     ┌────▼─────┐    ┌─────▼──────┐      (future: rdp-proxy [Rust],
     │ ssh-proxy│    │  pg-proxy  │              k8s-proxy [Go], …)
     │  (Rust)  │    │   (Rust)   │
     └────┬─────┘    └─────┬──────┘
          └─────── inject creds · proxy · record ───────┘
                           │
                     target assets
```

**Approach A (control plane brokers, workers enforce):** the control plane holds all security-critical state (identity, graph, grants, vault); workers are stateless enforcers that obtain authorization + just-in-time credentials per session over gRPC. Per-session latency cost is negligible for human access; secrets stay centralized and revocation is immediate.

## 6. Components

### 6.1 Control plane (Go)

Narrowly-scoped internal modules:

- **API server** — REST + OpenAPI (huma or chi+swaggo) generating a typed TypeScript client; WebSocket endpoints for live browser sessions; serves the embedded React SPA (Go `embed`).
- **Identity** — local users & groups (nested groups), argon2id password hashes, UI session cookies/JWT, personal API tokens for the CLI.
- **Authorization** — OpenFGA (in-process or sidecar, same Postgres) holds the relationship graph: groups, folders, roles, role bindings (§7).
- **Role service** — CRUD for **custom roles** (admin-defined capability bundles + connection identity + escalation/approval policy) stored in Postgres; resolves roles → the fixed capability vocabulary.
- **Resource catalog** — assets (SSH host, Postgres DB) and folders (hierarchical), each with labels (env/sensitivity).
- **Credential vault** — target credentials encrypted at rest via envelope encryption (KMS-wrappable data key; MVP uses a config-provided master key with NaCl secretbox). Decrypted only to hand to a worker for a live, authorized session.
- **JIT / approval engine** — access requests, approval workflow (in-app for MVP), time-boxed grants written as temporary OpenFGA tuples, a reaper that revokes on expiry and signals teardown. One engine serves both pre-session and inline (Postgres) approvals.
- **Audit log** — append-only, hash-chained tamper-evident entries in Postgres (§10).
- **Recording service** — stores recording blobs to the object store; metadata + per-chunk integrity hashes in Postgres.
- **Worker registry** — watches k8s Endpoints per worker pool; exposes the live roster to the gateway over gRPC. The *only* k8s-coupled component (sets up sub-project #5).
- **Token minter** — issues short-lived **PASETO v4.public (ed25519)** session tokens bound to a `grant_id`; gateway/workers verify with the public key; workers introspect the grant at session start so revocation is immediate.

### 6.2 Gateway (Rust)

Thin and stable. `tokio` + `rustls`. Responsibilities:
- Terminate client TLS / WSS.
- Validate the session token (signature + control-plane grant introspection).
- Read target protocol + pool from the token framing (our own CLI/browser clients present it in a small handshake — the gateway never sniffs the protocol).
- **Session-aware least-connections** placement onto a healthy worker; **pin** the connection for the session's lifetime.
- Forward the still-native byte stream to the worker over internal mTLS.
- Propagate teardown when the control plane revokes a grant.

It does **not** terminate SSH/Postgres — that protocol-agnosticism is what keeps future workers language-free. It learns its worker roster from the control plane (which watches k8s), so it stays k8s-agnostic.

### 6.3 Protocol workers (Rust)

Stateless; all authority comes from the token + per-session control-plane calls, so each pool scales by replica count.

- **`ssh-proxy`** (`russh`) — presents an SSH server to the client, authenticates the session via token, calls the control plane for target + injected credential, opens the upstream SSH connection, proxies the channel, records the PTY stream. **No inline TTY command gating** (see §9.3).
- **`pg-proxy`** (`pgwire` + `sqlparser-rs`) — two ingress modes:
  - **wire passthrough** for the CLI's local `psql` (full Postgres wire protocol),
  - **query-console API** for the browser (SQL string in → JSON result out).
  Both parse and classify every statement, enforce inline per-statement approval + tiered step-up (§9.2), fetch injected DB credentials, proxy to the target, and record every statement.

## 7. Access model & ReBAC schema

The access model separates **what a role means** (control-plane data) from **who holds it** (OpenFGA graph), mirroring Kubernetes RBAC (Role + RoleBinding). This is the core of the design.

### 7.1 Capabilities — fixed vocabulary (enforced by code)

The workers implement a small, stable set of primitives; roles are composed from these. Roles cannot invent capabilities the enforcement code doesn't implement.

- **Connection identity** — which target account/credential to inject (SSH login user; Postgres login role).
- **Actions** — `connect`, `read`, `write`, `ddl`, `admin`.
- **Postgres privilege tiers** — `readonly` (SELECT), `readwrite` (INSERT/UPDATE/DELETE), `ddl` (CREATE/ALTER/DROP); which tiers require approval; max step-up tier; step-up TTL bounds.
- **Approval policy** — N-of-M, approver source, request TTL, auto-approve conditions.
- **Session limits** — max session duration; recording always on.

### 7.2 Role — admin-defined capability bundle (the "custom role")

A Postgres row scoped to a resource type, composed from the capability vocabulary. Examples:
- **PG-ReadOnly** → Postgres, injects login `readonly`, `readonly` tier only, no approval.
- **PG-Migrator** → Postgres, injects login `migrator`, tiers up to `ddl`, `ddl` requires 1 approval, step-up TTL ≤ 15 min, session ≤ 2 h.
- **SRE-Prod-SSH** → SSH, target user `deploy`, session ≤ 1 h, pre-session elevation.

Custom roles and custom approval flows are the same edit — the escalation/approval policy lives on the role.

### 7.3 RoleBinding — assigns a Role to subjects at a scope (in OpenFGA)

```
type group
  relations
    define member: [user, group#member]              # user-in-group-in-group

type role                                              # graph handle for a role definition
  relations
    define admin: [user, group#member]                 # who may edit the role

type folder
  relations
    define parent: [folder]
    define approver: [user, group#member] or approver from parent

type asset
  relations
    define parent: [folder]
    define approver: [user, group#member] or approver from parent

type role_binding
  relations
    define role:        [role]                          # which custom role
    define scope:       [folder, asset]                 # bind at a folder → whole subtree
    define assignee:    [user, group#member]            # standing access (nested groups ✔)
    define requestable: [user, group#member]            # "permission to ask for permission"
```

### 7.4 Resolution & the three visibility tiers

Discoverability is itself a permission. Against any asset a user is in exactly one of:
1. **Active** — a binding where the user is `assignee` (standing) or a live JIT grant → can connect now.
2. **Requestable** — a binding where the user is `requestable` but not active → visible-but-locked, may request.
3. **Invisible** — no applicable binding → existence not disclosed.

Resolution (control plane, using the graph, honoring folder inheritance + nested groups):
- **Applicable bindings(U, A)** = RoleBindings whose `scope` is A or an ancestor folder.
- **Active roles(U, A)** = roles of applicable bindings where `assignee(binding, U)`, plus live grant bindings.
- **Requestable roles(U, A)** = roles of applicable bindings where `requestable(binding, U)`, minus active.
- **Visible(U, A)** = Active ∪ Requestable is non-empty.
- **Capabilities(U, A)** = union of the capability sets of the active roles (resolved from the DB).
- **Approvers(A)** = `ListUsers(A, approver)` (inheritable relation).

### 7.5 API enforcement rules (load-bearing)

- **Catalog / search** → computed server-side from the graph (OpenFGA `ListObjects`-style). The result set *is* the visible set; never "fetch all, filter client-side."
- **Request access** → check the user holds a `requestable` binding for the requested role on the asset. If not, respond **404, not 403** (a 403 leaks existence/topology). Direct references to any non-visible asset also 404.
- **Connect** → check an active role/grant. If only requestable, the response instructs the user to request, not connect.

## 8. JIT access flow (end to end)

1. User runs `jumpgate connect prod-db --role pg-migrator --duration 2h` (or clicks **Request** in the UI).
2. Control plane checks the user holds a `requestable` (or already `assignee`) binding for that role on the asset. If eligible-only, it creates a **PENDING** AccessRequest capturing the **reason**.
3. Approver approves in the UI → control plane writes a **time-boxed grant** (temporary RoleBinding / `assignee` edge with expiry) and mints a **session token**.
4. Client connects to the **gateway** with the token; gateway validates + load-balances to an `ssh-proxy` / `pg-proxy` worker.
5. Worker introspects the grant, fetches target + **injected credential** (per the role's connection identity), opens the upstream, proxies, and **records**.
6. On expiry/revoke, the reaper deletes the grant tuple and signals gateway + worker to **kill the live session**.
7. Every step is written to the **audit log**.

Approval timing is a **policy value on the role**: `pre-session` (request before connect) or `inline` (Postgres per-statement). Both use the same approval engine.

## 9. Privilege escalation

### 9.1 Two timings, one engine

- **Pre-session** — request a (higher-privilege) role before connecting; the injected credential carries that privilege. Used by **SSH** and as the default for Postgres roles.
- **Inline** — during a live session, a specific action pauses pending approval, then auto-resumes. Used by **Postgres**.

### 9.2 Postgres — inline per-statement approval + tiered step-up

`pg-proxy` parses each statement (`sqlparser-rs`) and classifies it to a **privilege tier**. A statement above the session's current tier **pauses the data path**, emits an `ApprovalRequest` to the control plane, shows the user an inline notice, and awaits a decision (timeout → auto-deny). Two grant shapes offered:

- **Approve once** — run this single statement at the required tier, then revert.
- **Elevate to tier X for N minutes** — a **session-scoped, time-boxed step-up**: subsequent in-tier statements run without re-prompting until it expires, then auto-reverts. Reuses the grant + approval + reaper machinery (a minutes-long grant).

**Enforcement is defense-in-depth:** on approved step-up the proxy also raises the DB session's effective privilege (`SET ROLE <tier_role>` / credential swap) and reverts (`RESET ROLE`) on expiry, so the database enforces the tier even if the proxy gate were bypassed.

**UX:** the rich inline elevation UX (approve-once vs elevate-for-N-min) lives in the **web SQL console**. The wire-protocol `psql` path gets basic gating (blocked statement returns a Postgres error/NOTICE with instructions); step-up from raw `psql` is requested via the CLI/UI side channel.

### 9.3 SSH — pre-session only (MVP)

SSH keeps it simple: escalation happens **before** connecting (request the role whose injected credential carries the needed privilege). No inline TTY `sudo` gating in the MVP — parsing commands from an interactive PTY stream is not a robust enforcement boundary. (Future options, later sub-projects: injected-sudo-password gating for an agentless inline path; an opt-in host-side sudo/PAM plugin for airtight control.)

## 10. Session recording & audit

- **Recording** — SSH terminal as **asciicast v2**; Postgres as a structured statement log (statement, tier, timing, rows, approval reference). Blobs → object store; per-chunk SHA-256 → Postgres.
- **Audit** — append-only, **hash-chained** entries (`entry_hash = sha256(prev_hash ‖ canonical(entry))`) so any tampering breaks the chain. Every request, reason, approval, grant, session start/stop, step-up, and expiry is recorded. (SIEM export = sub-project #6.)

## 11. Clients

- **CLI** (Go, `cobra`) — `jumpgate login`, `jumpgate connect <asset> --role <role> [--duration]`; opens the local tunnel and hands off to the user's own `ssh` / `psql`.
- **Browser** (React + TypeScript + Vite SPA, embedded in the control-plane binary; shadcn/ui + Radix + Tailwind + TanStack Table) — admin console (assets, folders, groups, roles, bindings, requests, audit), approvals, **xterm.js** SSH terminal, and a **web SQL console** for Postgres (the primary surface for inline step-up UX). Live sessions ride a WSS connection to the gateway.

## 12. Interfaces / contracts (defined once, so new workers are cheap)

- **Session token** — PASETO v4.public; claims `{grant_id, user, asset, role, protocol, exp}`.
- **Worker ↔ control plane** — gRPC (`Authorize`, `FetchCredential`, `RequestApproval`, `PushRecordingChunk`, `EmitAudit`, `WatchTeardown`). Protos in `/proto`; `buf` codegen for Go + Rust.
- **Gateway ↔ worker** — internal mTLS stream with a length-prefixed header frame (`session_id`, `protocol`), then raw passthrough.
- **Worker registry (gateway ↔ control plane)** — gRPC stream of the live worker roster per pool.

## 13. Deployment

- **Helm chart** — Deployments for `control-plane`, `gateway`, `ssh-proxy`, `pg-proxy`; Postgres + MinIO as subcharts (or bring-your-own). The **gateway is the only externally exposed Service**.
- **docker-compose** — single-node developer/demo setup.
- **Config** — env + mounted config; master encryption key via secret; OpenFGA store bootstrap on first run.

## 14. Repo layout (monorepo)

```
/control-plane        Go   (API, identity, authz, roles, vault, JIT/approvals, audit, registry)
/gateway              Rust (session router / load balancer)
/workers/ssh-proxy    Rust
/workers/pg-proxy     Rust
/proto                shared gRPC contracts (buf)
/web                  React + Vite SPA
/cli                  Go (cobra)
/deploy/helm          Helm chart + docker-compose
/docs                 specs and design docs
flake.nix flake.lock  Nix devshell (all toolchains + tooling)
.envrc                direnv (`use flake`)
rust-toolchain.toml   pinned Rust toolchain (via rustup)
go.work               Go workspace (control-plane + cli)
Cargo.toml            Rust workspace (gateway + workers)
Makefile              task entrypoints (wraps tools from the devshell)
.pre-commit-config    fmt/lint hooks (via git-hooks.nix)
```

## 15. Development environment (Nix devshell)

Development uses a **Nix flake devshell** with **direnv**, so every contributor (and CI) gets one pinned, reproducible toolchain regardless of host. This follows the proven pattern in `ironcore-net-xdp` (a sibling polyglot Go+Rust repo).

- **`.envrc`** = `use flake` → direnv auto-enters the shell on `cd`.
- **`flake.nix`** provides the full toolchain and dev tooling; `flake.lock` pins nixpkgs. Structured with `flake-utils.eachDefaultSystem` (Linux + macOS).
- **Go** — pinned to the `go.work`/`go.mod` minor's latest patch via the `go-overlay` (`go-bin.fromGoMod`), so the shell tracks patches without drifting ahead of the declared minor.
- **Rust** — managed by `rustup`, pinned via `rust-toolchain.toml` (stable channel + `rustfmt`, `clippy`); MVP has no eBPF/nightly needs.
- **Pre-commit** — via `git-hooks.nix` (cachix): `rustfmt`/`clippy` for Rust, `gofmt`/`golangci-lint` for Go, plus web formatting (`prettier`/`eslint`). Wired through the flake's `shellHook`.
- **Tooling in the shell** (bare tool names, no host paths — the Makefile wraps them):
  - Protobuf/gRPC codegen: `buf`, `protobuf`, `protoc-gen-go`, `protoc-gen-go-grpc` (Go side); `prost`/`tonic` build via `cargo` (Rust side).
  - Rust helpers: `cargo-nextest`, `cargo-watch`, `cargo-edit`.
  - Frontend: `nodejs` + `pnpm` for the React/Vite SPA.
  - Data services for local dev/tests: `postgresql` client, `openfga` CLI, MinIO client (`mc`); containers for integration tests via `docker`/`testcontainers`.
  - Deploy/dev-cluster: `kubernetes-helm`, `kubectl`, `kind`, `docker-compose`.
- **Env vars** set by the shell as needed (e.g. `PROTOC`, `RUST_BACKTRACE=1`, test datastore URLs).
- **Makefile** is the task entrypoint (`make gen`, `make test`, `make lint`, `make up`), expected to run inside `nix develop` / direnv so scripts stay host-agnostic.

The concrete `flake.nix` is authored as the **first task of the implementation plan** (repo scaffolding), not part of this design.

## 16. Security considerations

- **Secret centralization** — target credentials live only in the control-plane vault; workers receive a decrypted credential only for a live, authorized session and never persist it.
- **Least privilege / no enumeration** — discoverability is permission-gated (§7.4–7.5); 404-not-403 hides existence; catalog is computed server-side.
- **Token scope & revocation** — short-lived PASETO bound to a single grant; workers introspect the grant at session start; grant deletion tears down live sessions.
- **Defense-in-depth for DB elevation** — DB role tracks the approval tier (§9.2).
- **Tamper-evident audit** — hash-chained entries; recordings hashed per chunk.
- **Transport** — client TLS/WSS at the gateway; mTLS gateway↔worker and worker↔control-plane.
- **Attack-surface minimization** — only the gateway is exposed; the control plane and workers are cluster-internal.

## 17. Testing strategy

- **Go** — unit tests + `testcontainers` integration (Postgres, OpenFGA) for identity, authz resolution (nested groups, folder inheritance, visibility tiers), roles/bindings, JIT/approval engine, audit hash-chain.
- **Rust** — unit tests + integration against a dockerized `sshd` (russh proxy path) and Postgres (pgwire passthrough + statement classification + tiered step-up + `SET ROLE` enforcement).
- **End-to-end** — a compose harness driving `jumpgate connect` through gateway → worker → target, asserting: access decision correctness, credential injection, recording produced, audit entries chained, grant expiry tears down the session, and a Postgres step-up prompt→approve→resume cycle.

## 18. Out of scope for the MVP (YAGNI)

OIDC/SAML/SCIM; RDP; k8s access; operator/CRDs; MySQL/Mongo; inline DLP/command-blocking; SSH inline sudo gating; host-side PAM plugin; Slack/Teams approvals; SIEM export; HA/multi-region.

## 19. Key decisions log

| Decision | Choice | Rationale |
|---|---|---|
| Backend split | Go control plane + Rust data plane | Go wins operator/authz/SSO/velocity; Rust wins proxy perf/safety and future RDP |
| Data plane shape | Two-tier: gateway + per-protocol workers | Independent per-protocol scaling + per-protocol language freedom |
| Proxy posture | Agentless L7 gateway | Lowest adoption friction; best JIT/DLP fit |
| Auth interaction | Approach A (control plane brokers) | Centralized secrets, immediate revocation, stateless workers |
| Access model | Custom Role + RoleBinding over OpenFGA | Enterprise custom roles; graph does relationships, DB holds meaning |
| Discoverability | Permission-gated (`requestable`) + 404-not-403 | Least privilege / no enumeration |
| Postgres escalation | Inline per-statement + time-boxed tiered step-up | "Access when you need it" done robustly on a structured protocol |
| SSH escalation | Pre-session only (MVP) | TTY command parsing isn't a robust boundary; keep MVP honest |
| Session token | PASETO v4.public | Simpler, misuse-resistant vs JWT |
| Identity (MVP) | Local accounts | Fastest to iterate; SSO is sub-project #2 |
| Authz engine | OpenFGA (embedded) | Go-native, simple DSL, CNCF |
| CLI language | Go (cobra) | Shares API client; clean static cross-compiles |
| Frontend | React + Vite SPA embedded in backend | Teleport/hoop pattern; largest ecosystem for data-heavy admin UI |
| Dev environment | Nix flake devshell + direnv | One pinned reproducible toolchain across contributors + CI (per `ironcore-net-xdp`) |

## 20. Open questions / risks

- **Scoped time-boxed grant encoding in OpenFGA** — the exact tuple encoding for "grant role R to user U on asset A for T minutes" (temporary RoleBinding vs temporary `assignee` edge vs contextual tuples) needs a short spike in the plan; pick the encoding that makes the reaper and teardown simplest.
- **Postgres step-up over raw `psql`** — the side-channel step-up UX for wire-protocol clients is less elegant than the web console; validate the NOTICE/error + CLI-request flow with a real `psql`.
- **`SET ROLE` model** — confirm the injected login can `SET ROLE` across the intended tiers (or use per-tier injected credentials); verify revert-on-expiry semantics under an open transaction.
- **Recording volume** — asciicast + per-chunk hashing storage growth; retention policy is deferred but note it.
- **Compliance claims** — validate PCI/ISO/HIPAA specifics against primary standards before any public claim (per research caveat).
