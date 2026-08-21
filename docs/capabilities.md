# Capabilities

The **capability vocabulary** — the primitive verbs a role grants. A capability
names *what you may do*: either a **data-plane** action on an asset (open an SSH
session, run a DDL statement, impersonate a k8s identity) or a **management-plane**
action on the API (onboard an asset, create a role, bind it, manage users). Roles
bundle capabilities; the authorizer answers "does this user hold a role — at the
relevant scope — whose capabilities cover the requested action?" The same grammar
and glob matcher serve both halves; they differ only in *where* they're enforced
(worker vs. warden) and *what scope* they're checked at (see the two sections
below).

> **Status:** capabilities are now enforced in two places. **(1) Management plane
> — enforced by warden.** Every management RPC (catalog / access / identity /
> vault / recording admin) is gated by a capability check in the handler
> (`requireCap`); this *replaced* the old boolean `is_admin` gate — see
> [Management-plane capabilities](#management-plane-capabilities) below. **(2) Data
> plane — enforced by the workers.** The **ssh-proxy (M4) enforces `ssh:*`** at a
> live session; `db:*` / `k8s:*` land with their proxies (M5 / later). The
> **grammar**, format validation, and glob matcher (`CapMatch`) are shared by
> both.

## Grammar

A capability is a **colon-delimited path of segments**:

```
scope:action[:qualifier…]
```

- It is **always scoped** — at least **two** segments (`ssh:connect`, not
  `connect`). A bare `admin` is rejected.
- Each segment is **lowercase alphanumeric with internal hyphens**:
  `[a-z0-9]+(-[a-z0-9]+)*` (e.g. `cluster-admin`). No uppercase, no leading/
  trailing/empty segments.
- The first segment is the **scope** (the protocol/subsystem: `ssh`, `db`,
  `k8s`), the second the **action**, and any further segments are **qualifiers**
  (`k8s:impersonate:cluster-admin`).

The format is validated at **`CreateRole`** by protovalidate (regex in
[`catalog.proto`](../proto/jumpgate/catalog/v1/catalog.proto), the
`CreateRoleRequest.capabilities` field). Invalid strings are rejected with
`InvalidArgument` before the role is stored:

| Rejected | Why |
|---|---|
| `admin` | unscoped (only 1 segment) |
| `*` | unscoped |
| `k8s:` | empty trailing segment |
| `k8s:**:x` | `**` is not the final segment |
| `DROP TABLE` | space / uppercase — not a valid segment |
| `K8s:connect` | uppercase |

Stored capability strings are **jsonb** on the `roles` row
(`roles.capabilities`, a JSON array of strings).

**The one bare-wildcard exception — `**`.** A standalone `**` is a valid stored
pattern (the grammar allows it alongside the `scope:action…` forms) and, via
`CapMatch`, matches **every** capability at any depth. It is the **`admin`
role's** capability: the bootstrap admin is an ordinary user holding a role whose
capabilities are `["**"]`, bound globally. (`**` is still rejected as a *middle*
segment — `k8s:**:x` — and a bare `*` / `admin` are still rejected.)

## Glob patterns

A role's **stored** capability list may contain **glob patterns**. The
**requested** capability at check-time is always **concrete** (a worker asks
about a specific operation, never a wildcard). Two wildcards exist:

- `*` matches **exactly one** segment. It never crosses a `:`.
- A trailing `**` matches **one-or-more remaining** segments, and may appear
  **only as the final segment**.

Matching is done by [`CapMatch(pattern, requested)`](../warden/internal/authz/capabilities.go),
the single auditable home of the glob semantics. `Check` unions the capability
sets of all roles the user holds on the asset and returns `true` if any stored
pattern `CapMatch`es the requested capability.

| Pattern | Matches | Does NOT match |
|---|---|---|
| `k8s:*` | `k8s:connect`, `k8s:access` | `k8s:impersonate:cluster-admin` (3-seg) |
| `k8s:*:*` | `k8s:impersonate:cluster-admin` | `k8s:connect` |
| `k8s:impersonate:*` | `k8s:impersonate:cluster-admin` | `k8s:connect` |
| `k8s:**` | all `k8s` caps, any depth | `k8s` (needs ≥1 segment after) |
| `*:connect` | `ssh:connect`, `db:connect`, `k8s:connect` | `ssh:access` |
| `db:ddl` (concrete) | `db:ddl` only | `db:ddl:foo` |

### Safety properties

- `*` is exactly **one** segment and **never crosses a `:`** — so `k8s:*`
  cannot reach into `k8s:impersonate:cluster-admin`. Widening one level requires
  writing `*` at each level (`k8s:*:*`).
- A **concrete** pattern never matches deeper: `db:ddl` grants `db:ddl` and
  nothing under it.
- `**` is the **explicit, auditable** "this whole scope, at any depth" grant.
  Someone reading a role's capability list sees `k8s:**` and knows it is broad;
  breadth is never accidental.
- `CapMatch` **fails closed** on a malformed non-final `**` (`k8s:**:x`): rather
  than silently dropping the segments after `**` (which would over-match), it
  returns `false`. The proto grammar already rejects such patterns at
  `CreateRole`; `CapMatch` enforces the same invariant defensively so a pattern
  reaching it via a non-proto path (direct SQL, a future writer) can never match
  more than its literal segments intend.

## Management-plane capabilities

The **management API** (creating folders/assets/roles/bindings/policies, managing
users/groups, vault CAs/secrets, reading recordings) is governed by capabilities
too — but here **warden both decides *and* enforces** them directly in the RPC
handler (there is no worker in the loop). This replaced the old boolean
`is_admin`: there is no admin flag anymore, only capabilities.

### Scope — global / folder / asset

A management capability is checked at a **scope**, not just "on an asset":

- **global** — system-wide operations (create a user, a top-level folder, a global
  role; CA init). A capability is held globally via a **scopeless role binding**
  (a `role_binding` with neither `scope_folder_id` nor `scope_asset_id`).
- **folder** — operations within a folder subtree (onboard an asset *in* `prod`,
  manage roles/bindings/policies there). A folder-scoped binding confers the cap.
- **asset** — operations on one asset (update its config, write its stored secret).

`CapabilitiesOnScope(user, scope)` returns the caps the user holds there:
globally-held caps **plus** — for a folder/asset scope — caps held on the object
**and every ancestor folder**. So management authority **cascades *down* the
folder tree**: a cap granted at `prod` applies to `prod`, its sub-folders, and all
their assets, with no extra wiring. (This folder cascade is management-specific;
it does not use the data-plane held-closure's opt-in `parent` role-grants.)
`requireCap(cap, scope)` in each handler = `CapabilitiesOnScope(...).Allows(cap)`
→ else `PermissionDenied`. The admin's global `**` satisfies every check.

### No-escalation subset rule

Binding a role, making it requestable, or wiring the role-grant graph is a
**grant** of that role's capabilities — so it is guarded: you may bind/grant role
`R` at scope `S` only if **every capability in `R` is subsumed by what you
yourself hold at `S`** (`requireGrantable` → `Covers` pattern-subsumption). You
can never grant authority you don't have. The admin (`**`) can grant anything; a
`prod`-admin holding `catalog:**`+`access:**`+`ssh:login:*` on `prod` can grant ≤
that within `prod`, but cannot grant `identity:*` or bind a global `admin` role.
(Applies at `CreateRoleBinding`, `CreateRequestPolicy`, `AddRoleGrant` — the last
checks the **recipient** `role_id`, the role that gets conferred.)

### The vocabulary

`<service>:<resource>:<verb>`, same grammar and globs as everything else.
**Scope** is where the cap must be held for the gated RPCs; identity/CA/grant-
oversight ops are **global** this cut (folder- and group-scoped delegation of
those is a follow-up).

| Capability | Grants (management RPC) | Scope |
|---|---|---|
| `catalog:folder:create` | create a folder | parent folder (global if top-level) |
| `catalog:folder:read` | resolve/list folders | folder / global (list) |
| `catalog:asset:create` | onboard an asset | the target folder |
| `catalog:asset:read` | get/list assets, resolve an asset | the asset / folder |
| `catalog:asset:update` | change an asset's config | the asset |
| `access:role:create` | create a role | the role's folder (global if global role) |
| `access:role:read` | get/resolve/list roles, list grants, explain | the role's folder / global |
| `access:role:update` | add/remove role-rewrite grants (`role_grants`) | the role's folder |
| `access:binding:create` | bind a role to a subject (+ subset rule) | the binding scope |
| `access:binding:read` | list role bindings | global |
| `access:binding:delete` | remove a binding | the binding's scope |
| `access:policy:create` | create a request policy (+ subset rule) | the policy scope |
| `access:policy:read` | get/list policies, list subjects, resolve approval | the policy's scope / asset |
| `access:policy:update` | update a request policy | the policy's scope |
| `access:policy:delete` | delete a request policy | the policy's scope |
| `access:policy:manage-subjects` | add/remove requester/approver subjects | the policy's scope |
| `access:grant:read` | list all JIT access grants (oversight) | global |
| `access:grant:revoke` | revoke another user's grant (oversight) | global |
| `identity:user:create` | create a user | global |
| `identity:user:read` | get/resolve/list users | global |
| `identity:user:deactivate` | deactivate / reactivate a user | global |
| `identity:user:delete` | delete a user | global |
| `identity:group:create` | create a group | global |
| `identity:group:read` | resolve/list groups + members | global |
| `identity:group:add-member` | add a user/group to a group | global |
| `identity:group:remove-member` | remove a member | global |
| `identity:group:delete` | delete a group | global |
| `vault:ca:init` | initialize the SSH / mesh CA | global |
| `vault:ca:issue` | issue a mesh certificate | global |
| `vault:ca:read` | read a CA public key | global |
| `vault:key:init` | initialize the session key | global |
| `vault:secret:write` | set/delete an asset's stored secret | the asset |
| `vault:secret:read` | list an asset's secrets | the asset |
| `recording:read` | list / fetch / download session recordings | the recording's asset / global (list) |
| `**` | everything (the `admin` role) | any |

> A delegated folder-admin holds only the caps they were granted, so client-side
> **name/path resolution** (which is itself `*:read`-gated) may be unavailable for
> objects they can't read — they address such objects by **id**. Widening a
> delegate's read caps (`catalog:folder:read`, `access:role:read`, …) restores
> name-based use.

**Deferred:** group-scoped management (a group hierarchy + `scope_group_id` + an
`identity:group:view` visibility cap) so group administration can be delegated per
group subtree; scoped/filtered list-all endpoints. See the design doc for the full
per-RPC mapping.

## Where enforcement lives (data plane) — warden decides, workers enforce

This is the **Approach A** boundary (see
[architecture.md](architecture.md#data-plane-interaction-model-approach-a)).
Capabilities sit exactly on it, and the split is deliberate:

### warden (control plane) **DECIDES**

To warden, capability strings are **opaque tokens**. It does not know that
`db:ddl` means "run a `CREATE TABLE`" or that `k8s:impersonate:cluster-admin`
grants god-mode on a cluster. Given `(user, asset, capability)`, warden:

1. resolves which roles the user **holds** on the asset via the ReBAC graph —
   nested groups, standing `role_bindings`, and the `same_object` / `parent`
   rewrite rules in `role_grants` (`HoldsRole` / its forward-closure dual
   `heldCTE`; see [access-model.md](access-model.md#role-inheritance)),
2. **unions** the capability sets of those held roles,
3. answers `Check` — `true` iff some stored pattern `CapMatch`es the requested
   capability (glob-aware).

In one line: warden translates **roles-in-scope → the set of held capabilities
→ yes/no**. It never interprets the *meaning* of a capability.

### workers / proxies (data plane) **ENFORCE**

The proxy owns the **semantics** and the actual enforcement. For a live session
it:

1. **maps a concrete protocol operation → a capability** — e.g. a `CREATE TABLE`
   statement → `db:ddl`; opening a shell → `ssh:connect`; a k8s API request →
   `k8s:access` or `k8s:impersonate:cluster-admin`,
2. **checks** it against warden (`Check`, or a warden-issued short-lived
   decision / credential minted at session start),
3. **allows or denies**, and **configures the access** — inject the credential,
   set the k8s impersonation identity, `SET ROLE` on the DB connection, etc.

So the difference between `k8s:access` ("impersonate **as the requesting
user**") and `k8s:impersonate:cluster-admin` ("impersonate **as
cluster-admin**") is **worker-side semantics**: warden only sees two distinct
opaque tokens and answers yes/no on each; the k8s-proxy is what turns a
"yes" into an actual impersonation header.

> **Status:** the **SSH data plane is live** — the **ssh-proxy (M4) enforces
> `ssh:login:*`** at a real session (the broker mints the cert principals from the
> user's held login caps and the proxy gates the connection). The **`db:*` /
> `k8s:*`** verbs are still **planned** (pg-proxy M5; k8s a later sub-project) —
> defined-for-the-model, not yet enforced.

## Data-plane vocabulary

The protocol verbs a **worker** enforces at a live session (the management-plane
vocabulary is [above](#the-vocabulary)). Illustrative and **grows as workers
land**. `ssh:*` is enforced today (ssh-proxy, M4); `db:*` / `k8s:*` are
**defined-for-the-model** and land with their proxies.

| Capability | Meaning (worker-side) | Introduced with | Enforced today |
|---|---|---|---|
| `ssh:connect` | Open an SSH session to the target (the effective gate is `ssh:login:*`) | ssh-proxy (M4) | via `ssh:login:*` |
| `ssh:login:<account>` | Log in **as the OS account `<account>`** (`ssh:login:root`, `ssh:login:deploy`, or `ssh:login:*` for any allowed login). **Drives the SSH cert principals** the [CredentialBroker](architecture.md#vault--credentialbroker-m3d) mints: `ValidPrincipals = allowed_logins ∩ the user's held ssh:login:*` | vault/CredentialBroker (M3d); ssh-proxy (M4) | **Yes** — broker cert minting + ssh-proxy session gate |
| `db:connect` | Open a Postgres session | pg-proxy (M5) | No |
| `db:ddl` | Run a DDL statement (`CREATE`/`ALTER`/…) | pg-proxy (M5) | No |
| `db:read`, `db:write`, … | Finer per-statement tiers (`readonly`/`readwrite`/`ddl`); a role may bundle these or use the `db:*` glob | pg-proxy (M5) | No |
| `k8s:connect` | Reach the cluster API through the proxy | k8s-proxy (later sub-project) | No |
| `k8s:access` | Impersonate **as the requesting user** | k8s-proxy (later) | No |
| `k8s:impersonate:<role>` | Impersonate **as `<role>`** (e.g. `k8s:impersonate:cluster-admin`) | k8s-proxy (later) | No |

The exact per-protocol capability lists are settled **when each worker is
built** — the grammar and matcher are stable now, the protocol coverage is not.

## Related

- [access-model.md](access-model.md) — how roles bundle capabilities and how
  the ReBAC graph decides which roles a user holds.
- [architecture.md](architecture.md#data-plane-interaction-model-approach-a) —
  the control-plane-decides / worker-enforces split (Approach A).
