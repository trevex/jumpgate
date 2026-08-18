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
- **Credential vault** ⬜ — target credentials, envelope-encrypted at rest.
- **JIT / request engine (AccessRequestService)** 🟡 — `ResolveApproval` implemented; the `RequestAccess`/`Approve`/`Deny`/`Revoke` lifecycle, the `access_grants` table, the reaper, and teardown are **M3c**.
- **Request policies** 🟡 (M3b + Access-Model v2) one `request_policies` row per (role, scope) whose **existence makes the role requestable** there: role-level default (set at role definition — gates custom roles like `cluster-admin` to approval-only) + per-scope override, most-specific wins. Symmetric eligibility — requester = holders of `requester_role` on the scope ∪ explicit `requester` subjects; approver = holders of `approver_role` ∪ explicit `approver` subjects; both resolved via `HoldsRole`. No policy ⇒ not requestable. CRUD in `AccessService`; resolver (`EffectiveRule`, `IsApprover`, `IsEligibleRequester`) + `ResolveApproval` in `AccessRequestService`.
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

### Continuous revocation — live-session teardown ⬜ (M3c reaper + M4 gateway)

> **Design constraint, not yet implemented.** This is a load-bearing invariant
> that the M3c reaper and the M4 gateway/worker session registry must satisfy.

**Authorization is continuous, not connect-time only.** A session is authorized
for its whole lifetime, not just at the handshake. When the authorization a live
session depends on is revoked, that session must be **terminated**, not merely
blocked at the *next* connect. "Zero standing access" is only true if losing
access ends access *now*.

**Revocation sources** that must trigger teardown of any dependent live session:

| Source | Change |
|---|---|
| JIT grant | expires or is revoked (the M3c reaper) |
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

**Scope.** This spans **M3c** (reaper → teardown signal) and **M4** (gateway /
worker **session registry** + kill path). Keeping the **session ↔ grant/binding
mapping** and the **teardown RPC** in scope for those milestones is what makes
this invariant real rather than aspirational.

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

## Just-in-time access & escalation 🟡 (M3b policy / M3c workflow / M5 inline)

**The request flow (M3c):** `RequestAccess(role, asset)` → the effective
`request_policy(role, asset)` is resolved most-specific → the requester's
**eligibility** is checked (`IsEligibleRequester`: holds `requester_role` on the
asset ∪ explicit `requester` subject) → approvals are collected from the policy's
approvers (`IsApprover`: holds `approver_role` ∪ explicit `approver` subject),
N-of-M → on satisfaction a **time-boxed `access_grants` row** is written, joining
the requester's standing set until a reaper expires it. Policy resolution and the
eligibility/approver predicates are implemented (M3b + v2); the
request→grant→reaper workflow and the `access_grants` table are **M3c**.

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
authorizer's standing set becomes `role_bindings ∪ active access_grants` (M3c).

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
