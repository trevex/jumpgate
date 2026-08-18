# Capabilities

The **capability vocabulary** — the primitive verbs a role grants. A capability
names *what you may do* on an asset (open an SSH session, run a DDL statement,
impersonate a k8s identity). Roles bundle capabilities; the authorizer answers
"does this user hold a role on this asset whose capabilities cover the requested
action?"

> **Status:** the capability **grammar**, its **format validation** at role
> creation, and the **glob matcher** (`CapMatch`) that `Check` uses are
> **implemented** (this branch). What a capability *lets you do* — the mapping
> from a live protocol operation to a capability, and the actual enforcement —
> lives in the **data-plane workers, which are planned (M4/M5)**. So today warden
> validates capability strings and *decides* on them; **nothing enforces them at
> a live session yet**, because there are no workers.

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

## Where enforcement lives — warden decides, workers enforce

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

> **Status:** the workers are **planned (M4 gateway + ssh-proxy, M5 pg-proxy;
> k8s a later sub-project)**. Today warden validates capability strings and
> decides `Check`; **live enforcement lands with the proxies.**

## Initial vocabulary

Illustrative and **grows as workers land**. Everything below is
**defined-for-the-model**; column *Enforced today* is **No** across the board
because there are no workers yet.

| Capability | Meaning (worker-side) | Introduced with | Enforced today |
|---|---|---|---|
| `ssh:connect` | Open an SSH session to the target | ssh-proxy (M4) | No |
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
