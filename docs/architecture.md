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
                    │ JIT grants · vault · approvals · audit ·         │
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

- **API server** ✅ ConnectRPC (connect-go): AuthService + IdentityService + CatalogService served on the same HTTP server as /healthz; one handler speaks Connect + gRPC + gRPC-Web (no proxy). Auth via a bearer-token interceptor; validation via protovalidate; existence-hiding via CodeNotFound.
- **Identity** 🟡 (M2b: local users/groups/nested memberships + password login/opaque tokens + admin guard; OIDC/SAML/SCIM later). Initial admin seeded via `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` on first startup.
- **Authorization** ✅ (recursive-CTE Authorizer + catalog RPCs; OpenFGA remains a future drop-in behind the seam). See [Access model](#access-model).
- **Role service** ⬜ — custom roles as capability bundles.
- **Resource catalog** ✅ folders/assets/roles/role-bindings CRUD + per-user visibility catalog (CatalogService): ListVisibleAssets / GetAssetAccess resolve the caller's Active/Requestable/Invisible tiers via the Authorizer, with CodeNotFound existence-hiding.
- **Credential vault** ⬜ — target credentials, envelope-encrypted at rest.
- **JIT / approval engine** ⬜ — access requests, approvals, time-boxed grants, reaper.
- **Approvals** 🟡 (M3b) ApprovalRule per (role, scope): role-level default (set at role definition — gates custom roles like `cluster-admin` to approval-only) + per-scope override; approvers = holders of an approver-role on the requested scope ∪ explicit subjects; most-specific rule wins; no rule ⇒ not JIT-requestable. Resolver (`EffectiveRule`, `IsApprover`) + `ApprovalService` (admin CRUD + `ResolveApproval`).
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

## Access model

Relationship-based (ReBAC), accessed through an **`Authorizer` seam**. The M2a implementation resolves access with **recursive SQL (CTEs) over Postgres** — computing transitive nested-group membership, folder-subtree inheritance, and the Active/Requestable/Invisible tiers. An OpenFGA-backed implementation (embedded or sidecar) can be dropped in behind the same seam later; the relationship rows are stored tuple-shaped to make that swap mechanical.

The model separates *what a role means* from *who holds it* — modeled on Kubernetes RBAC (Role + RoleBinding). 🟡 (M2a: resolution implemented; M2b: REST catalog)

1. **Capabilities** — a fixed vocabulary the workers enforce (`connect`, `read`,
   `write`, `ddl`, `admin`, connection identity, escalation knobs). Not user-editable.
2. **Role** — an admin-defined bundle of capabilities scoped to a resource type
   (e.g. *PG-Migrator*, *SRE-Prod-SSH*). This is the customer's "custom role".
3. **RoleBinding** — assigns a role to subjects at a scope (folder or asset),
   as either standing (`assignee`) or requestable eligibility (`requestable`).

The recursive-CTE backend answers assignment/visibility/requestability (with nested groups
and folder inheritance); the control plane resolves roles → capabilities.

**Discoverability is a permission.** Against any asset a user is *Active*
(can connect now), *Requestable* (visible, may request), or *Invisible* (existence
undisclosed). The catalog is computed server-side from the graph; requests for
non-visible assets return **404, not 403**, so topology never leaks.

## Just-in-time access & escalation ⬜ (M3/M5)

One approval engine, two timings:

- **Pre-session** — request a (higher-privilege) role before connecting. Used by
  **SSH** (the injected credential carries the privilege; no inline TTY gating,
  which is not a robust boundary).
- **Inline** — during a live session, a specific action pauses pending approval,
  then auto-resumes. Used by **Postgres**: `pg-proxy` classifies each statement to
  a privilege tier (`readonly`/`readwrite`/`ddl`); a statement above the current
  tier pauses and offers **Approve once** or **Elevate to tier X for N minutes**
  (a session-scoped, time-boxed step-up, enforced at the DB via `SET ROLE`).

A JIT grant is a temporary RoleBinding edge with an expiry, reaped on timeout —
the same primitive for a 2-hour SSH grant or a 15-minute Postgres step-up.

## Audit & recording ⬜ (M3/M4)

Every request, reason, approval, grant, session start/stop, step-up, and expiry is
written to an append-only, **hash-chained** audit log
(`entry_hash = sha256(prev_hash ‖ canonical(entry))`) so tampering breaks the
chain. Sessions are recorded (SSH as asciicast v2; Postgres as a structured
statement log) to object storage with per-chunk hashes. SIEM export is a later
milestone.

## Key technology choices

See [decisions.md](decisions.md) for the rationale behind Go+Rust, the two-tier
data plane, agentless posture, OpenFGA, PASETO, and the frontend stack.
