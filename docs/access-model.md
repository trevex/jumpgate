# Access & Approval Model

How groups, folders, assets, roles, bindings, and approval rules interact to
decide **who can do what, where, and how they get there**. This is the
conceptual reference behind the `Authorizer` and `ApprovalResolver`.

> **Status:** the resolution described here (nested groups, folder inheritance,
> visibility tiers, approval rules) is **implemented** (M2 + M3b). *Activating* a
> requestable role via the approval workflow (the time-boxed grant) is **M3c**.
> **Role→parent-role inheritance** (a role hierarchy) is a **proposed extension**
> — see [Role inheritance](#role-inheritance); it is not implemented yet.

## Entities

| Entity | What it is |
|---|---|
| **User** | A local account (email, argon2id password, `is_admin` flag). |
| **Group** | A named set of subjects. A group's members are users *and/or other groups* → **nested groups**. |
| **Folder** | A container in a hierarchy (`parent_id`). Organizes assets and is the unit of **inheritance**. |
| **Asset** | A protected resource (an SSH host, a Postgres DB, a k8s cluster, …). Belongs to exactly one folder; carries free-form `labels`. |
| **Capability** | A fixed, code-enforced primitive (`connect`, `read`, `write`, `ddl`, `admin`, …). Not user-editable — the workers only understand these. |
| **Role** | An **admin-defined** named bundle of capabilities, scoped to a resource type (`asset` or `folder`). E.g. *PG-ReadOnly* = `[read]`, *cluster-admin* = `[connect,read,write,admin]`. This is the "custom role". |
| **RoleBinding** | Attaches a **role** to a **subject** (user or group) at a **scope** (folder or asset), as one of two **kinds**: `standing` (access now) or `requestable` (eligible to request). |
| **ApprovalRule** | Governs how a **requestable** role is activated: attached to a role (role-level default) with optional per-(role, scope) overrides. Carries `required_approvals` + approver sources. |

Relationship rows (`group_memberships`, `folders.parent_id`, `role_bindings`,
`approver` config) are stored **tuple-shaped**, so the whole model could be
mirrored into an external engine (OpenFGA) later without changing the domain.

## The two inheritance axes

Everything below flows from **two** kinds of inheritance:

1. **Nested-group membership** (transitive): if `alice ∈ sre` and `sre ∈ platform`,
   then `alice` is a member of `platform`. Any binding to `platform` applies to `alice`.
2. **Folder inheritance** (subtree): a binding or rule attached to a **folder**
   applies to **every asset and subfolder beneath it**, unless something more
   specific overrides it. A binding on the asset itself is the most specific.

Both are resolved with recursive SQL (CTEs) in `internal/authz` and
`internal/approvals`.

## Standing access — "what can I do right now?"

A user has a capability on an asset when they hold a **`standing`** RoleBinding
whose **role** includes that capability, where the binding's **subject** is the
user (or a group they're transitively in) and whose **scope** is the asset or any
ancestor folder.

**Worked example**

```
Groups:   alice ∈ sre ∈ platform
Folders:  prod ⊃ prod/db
Asset:    pg-prod  (in prod/db)
Role:     operator = [connect, read, write]   (resource_type: asset)
Binding:  platform → operator   STANDING   on folder prod
```

`alice` can `connect`/`read`/`write` on `pg-prod`:
- `platform` reaches `alice` via nested membership (sre → platform),
- the `prod` binding reaches `pg-prod` via folder inheritance (prod ⊃ prod/db ⊃ pg-prod),
- `operator`'s capabilities include those actions.

Add a new asset under `prod`, or a new engineer to `sre` → no new bindings
needed; the graph does the work.

## Requestable eligibility & visibility tiers — "what can I see / ask for?"

A **`requestable`** RoleBinding does **not** grant access — it makes the user
*eligible to request* that role. Discoverability is itself permission-gated.
Against any asset a user is in exactly one tier:

| Tier | Meaning | Comes from |
|---|---|---|
| **Active** | Can act now | a `standing` binding applies (directly or a live grant) |
| **Requestable** | Visible, may request | a `requestable` binding applies, but no standing one |
| **Invisible** | Existence not disclosed | no binding applies at all |

The catalog (`ListVisibleAssets`) returns **Active ∪ Requestable** only. A direct
lookup of an Invisible asset returns **`NotFound`, never `PermissionDenied`** — so
topology never leaks. `GetAssetAccess` reports the caller's active/requestable
roles on one asset (or `NotFound` if invisible).

## Approval — how a requestable role gets activated

Requesting a `requestable` role is gated by an **ApprovalRule**, keyed by
**(role, scope)**. The rule's primary home is the **role definition** — a
**role-level default** set when an admin creates the custom role. This is what
makes a powerful custom role (e.g. `cluster-admin`) **reachable only through
approval**: the gate travels with the role wherever it is requestable. A role
with **no** rule anywhere is **not JIT-requestable** at all (it can only be handed
out as a `standing` binding by an admin).

A rule carries:
- `required_approvals` — the **N-of-M** threshold.
- an optional **approver-role** — "whoever holds *this role* on the requested
  scope may approve" (evaluated as a `standing` binding on the asset or an
  ancestor folder, group-aware).
- optional **explicit approver subjects** (users/groups).
- **Approvers = approver-role holders ∪ explicit subjects.**

### Resolution (most-specific wins)

To activate role **R** on asset **A**, the effective rule is the most specific of:

```
(R, asset A)                      ← override on the asset itself      (wins)
(R, nearest ancestor folder of A) ← override on a folder up the tree
   … farther ancestor folders …
(R, role-level default)           ← the rule set at role definition   (fallback)
none  ⇒  NOT requestable
```

Because roles inherit down folders, requesting **R at a folder** (broad — cascades
to everything beneath) and **R at an asset** (narrow) start the walk at different
scopes → they can be **two different approval flows**. Getting broad `admin@folder`
is deliberately a different (usually heavier) approval than narrow `admin@asset`.

**Worked example**

```
Role:     cluster-admin = [connect, read, write, admin]  (resource_type: asset)
          role-level default rule: required_approvals=1, approver-role = owner
Folder:   k8s ; Asset: cluster-x (in k8s)
Binding:  eng → cluster-admin   REQUESTABLE   on folder k8s     (eligibility)
Binding:  dana → owner          STANDING      on folder k8s     (dana is an owner)
```

`alice ∈ eng` requests `cluster-admin` on `cluster-x`:
- `EffectiveRule(cluster-admin, cluster-x)` → the role-level default (no override) →
  requestable, needs **1** approval.
- Approvers = holders of `owner` on `cluster-x` (via the `k8s` folder) ∪ explicit →
  **dana** can approve.
- On approval (M3c): a **time-boxed `standing` cluster-admin binding** is written for
  alice on cluster-x; a reaper removes it at expiry, reverting her to requestable.

Now tighten a vital asset:

```
Rule override: (cluster-admin, asset cluster-prod)  required_approvals=2, no approver-role, explicit approvers=[group:sec-leads]
```

A request for `cluster-admin` on `cluster-prod` now needs **2** approvals from
**sec-leads only** — folder owners no longer qualify there. The override *replaces*
the inherited rule for that (role, scope).

## Role inheritance

There are **two different things** people mean by "role inheritance":

### 1. Folder inheritance of bindings & rules — **implemented**

A RoleBinding or ApprovalRule attached to a **folder** applies to every asset and
subfolder beneath it; a more specific binding/rule (nearer folder, or the asset
itself) overrides. This is the folder axis described above and is how "grant a
group operator on a folder → every asset inherits it" works. This is *scope*
inheritance — the same role flowing down the resource tree.

### 2. Role→parent-role capability inheritance (a role hierarchy) — **proposed**

> Not implemented yet. Today roles are **flat** capability bundles.

The idea: a role may declare a **parent role** and **inherit its capabilities
transitively**, so roles compose instead of duplicating:

```
cluster-viewer  = [connect, read]
cluster-operator extends cluster-viewer  → adds [write]      → [connect, read, write]
cluster-admin    extends cluster-operator → adds [admin]     → [connect, read, write, admin]
```

Proposed shape: add `roles.parent_role_id` (nullable, same `resource_type`),
resolve a role's effective capability set as the union over its parent chain
(cycle-guarded), and keep everything else (bindings, visibility, approval) working
on the *effective* set. Each role can still carry its own ApprovalRule, so
`cluster-admin` can require heavier approval than `cluster-operator` even though it
extends it. **This needs sign-off before implementation** (schema + capability
resolution change) — see the project design notes.

## How the pieces fit (one picture)

```
              members (nested)                    parent_id
   User ─────────────────────► Group        Folder ───────► Folder ──► … (tree)
    │                            │              │                        │
    │        subject             │ subject      │ contains               │
    └───────────────┐   ┌────────┘        ┌─────┘                        │
                    ▼   ▼                 ▼                              ▼
                 RoleBinding ── scope ──► Folder / Asset ◄── belongs ── Asset
                    │  (standing | requestable)                          
                    │ role                                               
                    ▼                                                    
                  Role ──► capabilities [ …fixed vocabulary… ]           
                    ▲            (parent_role_id → capability cascade — proposed)
                    │ governs activation of a *requestable* binding      
                 ApprovalRule (role-level default + per-scope override)  
                    └─ approvers = approver-role-on-scope ∪ explicit subjects, N-of-M
```

- **Access** (standing): Authorizer walks nested groups + folder ancestors to find
  applicable `standing` bindings → capabilities.
- **Discovery** (tiers): same walk over `standing` ∪ `requestable` → Active /
  Requestable / Invisible.
- **Activation** (requestable → standing): ApprovalResolver finds the most-specific
  rule for (role, scope), checks approvers, and (M3c) writes a time-boxed grant.
- **Audit**: every request/approval/grant/expiry is appended to the hash-chained
  log (see [architecture](architecture.md#audit--recording)).

## Related

- [architecture.md](architecture.md#access-model) — where this sits in the system.
- [decisions.md](decisions.md) — why ReBAC-over-SQL, custom Role+RoleBinding, the approval model.
