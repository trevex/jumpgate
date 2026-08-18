# Access & Approval Model

How groups, folders, assets, roles, bindings, and approval rules interact to
decide **who can do what, where, and how they get there**. This is the
conceptual reference behind the `Authorizer` and `ApprovalResolver`.

> **Status:** the resolution described here (nested groups, folder inheritance,
> visibility tiers, approval rules) is **implemented** (M2 + M3b). The
> **explicit ReBAC-light role-rewrite** model — user-definable roles plus
> `same_object` / `parent` rewrite rules, resolved by `HoldsRole` — is
> **implemented** (M3-roles); see [Role inheritance](#role-inheritance). A key
> consequence: folder cascade of **standing** access is now **explicit** (a role
> reaches a folder's descendants only if it declares a `parent` rewrite rule), no
> longer an automatic subtree cascade. *Activating* a requestable role via the
> approval workflow (the time-boxed grant) is **M3c**.

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
2. **Folder inheritance** (down the resource tree). This axis now resolves
   **differently for standing vs requestable access**:
   - For **standing / Active** access it is **explicit**: a role cascades from a
     folder to its descendants (child folders + assets directly in the folder)
     **only if the role declares a `parent` role-rewrite rule** (canonically
     `R ⊇ R via parent`). There is no automatic subtree inheritance — a folder
     binding with no `parent` rule confers access on the folder object alone.
     This is governed by the role-rewrite graph (see [Role inheritance](#role-inheritance)).
   - For **requestable** eligibility/visibility and for **ApprovalRule** resolution
     the old **implicit folder-subtree cascade is retained** (documented
     deferrals): a requestable binding or an approval rule attached to a folder
     still applies to every asset and subfolder beneath it, most-specific wins.

Nested-group membership and the requestable/approval folder walks are resolved
with recursive SQL (CTEs) in `internal/authz` and `internal/approvals`; standing
folder cascade is resolved through the explicit role-rewrite graph.

## Standing access — "what can I do right now?"

A user has a capability on an asset when they **hold** — per the explicit
role-rewrite resolution (`HoldsRole`) — a role that includes that capability on
that asset, backed by a **`standing`** RoleBinding whose **subject** is the user
(or a group they're transitively in). Concretely that binding is either on the
asset itself, or on an **ancestor folder for a role that declares a `parent`
cascade rule** (`R ⊇ R via parent`) — a folder binding for a role with no such
rule confers access on the folder object alone, not its descendants.

**Worked example**

```
Groups:   alice ∈ sre ∈ platform
Folders:  prod ⊃ prod/db
Asset:    pg-prod  (in prod/db)
Role:     operator = [connect, read, write]   (resource_type: asset)
Rewrite:  operator ⊇ operator  via parent      ← makes operator cascade down folders
Binding:  platform → operator   STANDING   on folder prod
```

`alice` can `connect`/`read`/`write` on `pg-prod`:
- `platform` reaches `alice` via nested membership (sre → platform),
- the `prod` binding reaches `pg-prod` because `operator` declares
  `operator ⊇ operator via parent`: holding `operator` on `prod` confers
  `operator` on `prod/db`, and on `pg-prod` in it (`HoldsRole` walks the
  `parent` rewrite from folder to descendants),
- `operator`'s capabilities include those actions.

**Without** the `operator ⊇ operator via parent` rule, the `STANDING` binding
would confer `operator` on the **folder object `prod` only** — not on `prod/db`
or `pg-prod`. The folder cascade of standing access is explicit; it is the rewrite
rule that does the work.

With the rule in place, adding a new asset under `prod`, or a new engineer to
`sre` → no new bindings needed; the graph does the work.

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

> **Note (deferral):** the **Active** and **Requestable** tiers resolve folder
> inheritance **differently** for now. Active/standing access uses the explicit
> role-rewrite graph (`parent` rules). **Requestable** eligibility still uses the
> **old implicit folder-subtree cascade** — a requestable binding on a folder
> makes every asset beneath it requestable, no rewrite rule required. Bringing
> requestable eligibility onto the rewrite engine ("rewrite-over-requestable") is
> future work.

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
  asset may approve", resolved via the role-rewrite graph (`HoldsRole`), the same
  explicit resolution as standing access (a direct binding on the asset, or an
  ancestor-folder binding for a role with a `parent` cascade rule), group-aware.
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
Rewrite:  owner ⊇ owner via parent      ← makes owner cascade down folders
Folder:   k8s ; Asset: cluster-x (in k8s)
Binding:  eng → cluster-admin   REQUESTABLE   on folder k8s     (eligibility)
Binding:  dana → owner          STANDING      on folder k8s     (dana is an owner)
```

`alice ∈ eng` requests `cluster-admin` on `cluster-x`:
- `EffectiveRule(cluster-admin, cluster-x)` → the role-level default (no override) →
  requestable, needs **1** approval.
- Approvers = holders of `owner` on `cluster-x` (resolved via `HoldsRole`) ∪ explicit.
  `owner` cascades `k8s → cluster-x` via its `owner ⊇ owner via parent` rule, so
  dana's folder binding confers `owner` on `cluster-x` → **dana** can approve.
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

Role inheritance is an **explicit ReBAC-light role-rewrite** model (M3-roles). It
replaces the old "flat roles + implicit folder cascade": role composition and
folder cascade are now expressed as **data** — declared rewrite rules — instead of
being implicit. This is *ReBAC-light* because the **object types are fixed**
(user / group / folder / asset) and only **roles and their rewrite rules** are
user-definable; it has none of OpenFGA's arbitrary-type generality.

### The rewrite rules — `role_grants`

A rewrite rule lives in `role_grants(role_id R, source_role_id S, via)` and means
**"holding `S` on the relevant object CONFERS `R`"**. There are two `via` kinds:

| `via` | Meaning | Use |
|---|---|---|
| `same_object` | Holding `S` on object `O` confers `R` on the **same** `O`. | **Role composition** — one role including another's capabilities on the same object. |
| `parent` | Holding `S` on a **folder** confers `R` on that folder's **children** (child folders + assets directly in it). | **Folder cascade** — the (now explicit) "grant on a folder flows down the tree" behaviour. |

Role composition is expressed via `same_object` rules (not a `parent_role_id`
capability union): e.g. `editor ⊇ owner via same_object` means anyone holding
`owner` on an object also holds `editor` there.

### Resolution — `HoldsRole`

`RoleResolver.HoldsRole(user, role, objectKind, objectID)` answers "does this user
hold this role on this object?" by **goal expansion**: it starts from the goal
`(role, object)` and rewrites it backwards through `role_grants`
(`same_object` → same object, `parent` → parent folder) until it reaches a goal
satisfied by a **direct `standing` binding** for the user or a group they are
transitively in. It is:

- **transitive** — chains of rules compose (`owner → editor → cluster_editor`);
- **group-aware** — a standing binding to a nested group satisfies the goal;
- **cycle-safe** — goals are deduped via `UNION`, so the finite goal set
  terminates (no silently-truncating depth limit).

An **explicit-only property** follows: a role cascades down folders **iff** it
declares a `parent` self-rule (`R ⊇ R via parent`); **no rule ⇒ no cascade**.

### Worked example

```
Roles:    owner, editor, cluster_editor, admin
Rewrite:  editor         ⊇ owner   via same_object
          editor         ⊇ editor  via parent
          cluster_editor ⊇ admin   via same_object
          cluster_editor ⊇ editor  via parent
Folders:  prod ⊃ prod/db
Asset:    pg  (in prod/db)
Groups:   alice ∈ sre
Binding:  sre → owner   STANDING   on folder prod
```

From the single `sre → owner STANDING on prod` binding, **alice** holds:

- `owner @ prod` — direct standing binding (via her group `sre`);
- `editor @ prod` — `editor ⊇ owner via same_object` on the same object;
- `editor @ prod/db` — `editor ⊇ editor via parent` cascades `editor` down;
- `cluster_editor @ pg` — `cluster_editor ⊇ editor via parent` reaches the asset
  `pg` from the `editor` she holds on its folder `prod/db`.

**bob** (in no group with a binding) holds **none** of these. And there is **no
path to `admin @ pg`**: nothing confers `admin` on `pg`.

### Introspection & administration

- **`ExplainRole(user, role, asset) → {holds, paths}`** answers "**why** do I hold
  this role?" — each `path` is the ordered rewrite chain from the requested
  `(role, asset)` down to the satisfying standing binding, with the subject
  (`user:…` / `group:…`). `holds` is `len(paths) > 0`.
- Admins manage the rules with **`AddRoleGrant`** / **`RemoveRoleGrant`** /
  **`ListRoleGrants`**.

Each role still carries its own ApprovalRule, so a composed role like
`cluster_editor` can require heavier approval than the roles it is built from.

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
                    ▲     (role_grants: R ⊇ S via same_object | parent — role-rewrite)
                    │ governs activation of a *requestable* binding      
                 ApprovalRule (role-level default + per-scope override)  
                    └─ approvers = approver-role-on-scope ∪ explicit subjects, N-of-M
```

- **Access** (standing): Authorizer resolves the explicit role-rewrite graph
  (`HoldsRole` / its forward-closure dual) over nested groups + `role_grants`
  (`same_object` / `parent`) down to `standing` bindings → capabilities.
- **Discovery** (tiers): Active from the same standing role-rewrite closure;
  Requestable from `requestable` bindings (retaining implicit folder cascade) →
  Active / Requestable / Invisible.
- **Activation** (requestable → standing): ApprovalResolver finds the most-specific
  rule for (role, scope), checks approvers, and (M3c) writes a time-boxed grant.
- **Audit**: every request/approval/grant/expiry is appended to the hash-chained
  log (see [architecture](architecture.md#audit--recording)).

## Related

- [architecture.md](architecture.md#access-model) — where this sits in the system.
- [decisions.md](decisions.md) — why ReBAC-over-SQL, custom Role+RoleBinding, the approval model.
