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

Capabilities are enforced in two places, sharing one grammar, format validation,
and glob matcher (`CapMatch`):

- **Management plane — enforced by warden.** Every management RPC (catalog / access
  / identity / vault / recording admin) is gated by a capability check in the
  handler (`requireCap`); this replaced the old boolean `is_admin` gate — see
  [Management-plane capabilities](#management-plane-capabilities) below.
- **Data plane — enforced by the workers.** The ssh-proxy enforces `ssh:*` at a
  live session today; `db:*` / `k8s:*` are defined for the model and land with
  their proxies.

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

**Scope notation.** Every check runs at one scope — `Global`, a **folder**, or an
**asset**. Three rules hold everywhere, so the table stays terse:

- **Cascade** — a folder check is satisfied by the cap held on that folder, on any
  **ancestor** folder, or **globally**. (`Global` caps satisfy every check.)
- **No folder home → `Global`** — an object with no `folder_id` (a *global* role or
  group) is checked at `Global`.
- **List-all → `Global`** — endpoints that scan the whole table
  (`ListRoleBindings`, `ListRequestPolicies`, `ListUsers`) require the read cap at
  `Global`; the per-object `Get`/`Resolve` forms use the object's own scope.
  `ListRoles` and `ListGroups` are exceptions — both are *visibility-filtered*
  path browses (see [Role and group browse](#role-and-group-browse--listroleslistgroups)
  below) and do **not** require a global read cap.
- **Catalog browse is NOT cap-gated.** `ListFolders` / `ListAssets` are
  *visibility-filtered* per-node: a caller sees a node iff it manages it (holds a
  management capability there) **or** has or can request access under it
  (Active ∪ Requestable). A capless caller receives an empty list — not
  `PermissionDenied`. Browsing a folder path the caller cannot see returns
  `NotFound` (existence-hiding). See
  [Catalog browse](#catalog-browse--listfolderslistassets) below.

**`catalog:folder:read` cascades READ across the whole subtree.** Held on a folder
`F`, it confers **read/visibility** of everything homed at or under `F` — descendant
sub-folders **and** the assets, roles, and groups within — so a delegate governing a
folder branch can browse and open its contents without also being granted
`catalog:asset:read`, `access:role:read`, and `identity:group:read` object-by-object.
It is the one cross-object read cap: every other read cap stays object-type-specific
(`catalog:asset:read` reads only assets, `access:role:read` only roles, etc.).
`catalog:folder:read` is **read-only** — it grants **no** authoring (create/update/
delete), **no** CONNECT (an `ssh:login:*` entitlement is still required to open a
session), and it is deliberately **excluded from the no-escalation subset rule**, so
holding it can never let a delegate bind or grant an object read cap they do not
themselves hold.

The **Scope** column below names the object whose scope the cap is checked at.
Where a single cap gates both a per-object read and a list-all, the list case is
noted in parentheses. User, CA/key, and grant-oversight caps are `Global`; catalog,
role, binding, policy, secret, recording, and **group** caps are folder/asset-scoped.

| Capability | Grants (management RPC) | Scope |
|---|---|---|
| `catalog:folder:create` | create a folder | parent folder (`Global` if top-level) |
| `catalog:folder:read` | resolve a folder by path/id (`ResolveFolder`); **read everything in the folder's subtree** — descendant sub-folders, assets, roles, and groups (see note below) | the folder |
| `catalog:folder:update` | rename or move a folder | the folder |
| `catalog:folder:delete` | delete a folder | the folder |
| `catalog:asset:create` | onboard an asset | target folder |
| `catalog:asset:read` | get / resolve an asset (`GetAsset`, `ResolveAsset`) | the asset |
| `catalog:asset:update` | change an asset's config | the asset |
| `catalog:asset:delete` | delete an asset | the asset |
| `access:role:create` | create a role | target folder (`Global` if a global role) |
| `access:role:read` | get / resolve a role; list a role's grants; explain a role | the role's folder |
| `access:role:update` | add / remove role-rewrite grants (`role_grants`) | the role's folder |
| `access:binding:create` | bind a role to a subject (+ subset rule) | the binding's scope |
| `access:binding:read` | list role bindings | `Global` |
| `access:binding:delete` | remove a binding | the binding's scope |
| `access:policy:create` | create a request policy (+ subset rule) | the policy's scope |
| `access:policy:read` | get a policy; list subjects; check approval eligibility; list policies | the policy's scope (approval-check: the asset; list-all: `Global`) |
| `access:policy:update` | update a request policy | the policy's scope |
| `access:policy:delete` | delete a request policy | the policy's scope |
| `access:policy:manage-subjects` | add / remove requester & approver subjects | the policy's scope |
| `access:grant:read` † | list **all** JIT access grants (oversight) | `Global` |
| `access:grant:revoke` † | revoke a grant **outside** your approver scope (oversight) | `Global` |
| `identity:user:create` | create a user | `Global` |
| `identity:user:read` | get / resolve / list users | `Global` |
| `identity:user:deactivate` | deactivate / reactivate a user | `Global` |
| `identity:user:delete` | delete a user | `Global` |
| `identity:group:create` | create a group | target folder (`Global` if a global group) |
| `identity:group:read` | resolve a group; list its members | the group's folder |
| `identity:group:add-member` | add a user / group to a group | the group's folder |
| `identity:group:remove-member` | remove a member | the group's folder |
| `identity:group:delete` | delete a group | the group's folder |
| `vault:ca:init` | initialize the SSH / mesh CA | `Global` |
| `vault:ca:issue` | issue a mesh certificate | `Global` |
| `vault:ca:read` | read a CA public key | `Global` |
| `vault:key:init` | initialize the session key | `Global` |
| `vault:secret:write` | set / delete an asset's stored secret | the asset |
| `vault:secret:read` | list an asset's secrets | the asset |
| `recording:read` | list / fetch / download session recordings | the recording's asset (unfiltered list: `Global`) |
| `**` | everything (the `admin` role) | any |

> **Moving a folder or asset requires the `…:update` capability on the moved node
> AND the `…:create` capability on the destination folder.** A rename needs only
> `…:update` on the node itself.

> **† `access:grant:*` is the cross-user *oversight* surface only.** Every user
> sees and acts on their **own** just-in-time access with **no capability
> required**: `ListMyRequests` / `ListMyGrants` return the caller's own
> requests/grants, `ListPendingApprovals` returns the requests the caller is an
> eligible **approver** for (per the request policy's approver set), and a user may
> always **revoke their own** grant. A **standing approver** for a grant's
> `(role, scope)` may also **revoke that grant** — the same eligibility that lets
> them approve the request lets them revoke the resulting access, no capability
> required. **Requesting** access is governed by the **request policy** (who may
> request which role at which scope) — not by a management capability.
> `access:grant:read` (list *everyone's* grants) and `access:grant:revoke` (revoke
> a grant you are **not** the subject of or an eligible approver for) gate only the
> org-wide oversight view; the normal request → approve → revoke-within-your-scope
> loop needs neither.

> A delegated folder-admin holds only the caps they were granted, so client-side
> **name/path resolution** (which is itself `*:read`-gated) may be unavailable for
> objects they can't read — they address such objects by **id**. Widening a
> delegate's read caps (`catalog:folder:read`, `access:role:read`, …) restores
> name-based use.

**Groups are folder-governed.** Like roles, a group can be homed in a folder
(`groups.folder_id`) — *governance-only* (it sets who may administer the group; it
does not affect membership or what the group is bound to). `identity:group:*` is
checked at the group's folder scope and cascades down the tree, so
`identity:group:create` on `team-a` delegates creating/managing groups under
`team-a`. Groups are addressed as **`<group>@<folder-path>`**
(e.g. `sre@team.demo`) — `@`, distinct from a role's `<role>.<folder-path>`.
Membership (incl. group-in-group nesting) is a separate, orthogonal axis and is not
folder-scoped. `identity:user:*` stays global (users are not folder-homed).
`ListGroups` is a **visibility-filtered path browse** — see
[Role and group browse](#role-and-group-browse--listroleslistgroups) below.

**Deferred:** per-group "owner" delegation (a `scope_group_id` binding scope for
single-group admin); folder-homing users; a subset guard on membership-adds. See
the design docs for the full per-RPC mapping.

### Catalog browse — `ListFolders`/`ListAssets`

Catalog lists differ from all other management RPCs: they are **visibility-filtered**
rather than cap-gated.

**Signatures.**

```
ListFolders(parent="", cascade=false, page_size, page_token) → [Folder…]
ListAssets (parent="", cascade=false, page_size, page_token) → [Asset…]
```

- `parent` — the folder to browse: empty string = root; otherwise a DNS-style
  dotted path (leaf-first, e.g. `db.prod`) or a UUID. Browsing a folder path the
  caller cannot see returns `NotFound` (existence-hiding).
- `cascade` — when `false` (the default) only **direct children** of `parent` are
  returned; when `true` the entire subtree is walked flat. The CLI's `--cascade`
  flag maps to this.
- `page_token` — an opaque keyset cursor. Reuse the same `parent` / `cascade`
  filters across pages; the CLI pages automatically and presents a merged result.
  An empty `next_page_token` in the response signals the last page.

**Visibility rule (per-node).** A caller sees a node if and only if it satisfies
at least one of:

1. **Manageable** — the caller holds a management capability at that node's scope
   (e.g. `catalog:asset:read` on the asset or an ancestor folder).
2. **Active or Requestable** — the caller holds a standing role that covers the
   node, or is eligible to request one via a request policy.

A caller with no entitlements to any node receives an **empty list** — not
`PermissionDenied`. There is no capability required to *attempt* a browse; the
result is simply empty when nothing is visible.

**List vs. detail split.** `ListFolders`/`ListAssets` return **navigation-only
bare nodes** (id, name, path). Per-node capabilities come from the detail RPCs:

- `GetAssetAccess(asset_id)` — the caller's `active_roles`, `requestable_roles`,
  and **`capabilities`** (the held-closure on the asset, object/folder-scoped,
  excluding global `**` so it faithfully mirrors connect ability).
- `GetFolderAccess(folder_id)` — the caller's management **`capabilities`** on
  the folder.

Call these after navigating to a node the list revealed.

### Role and group browse — `ListRoles`/`ListGroups`

Like the catalog browse, role and group lists are **visibility-filtered rather than
cap-gated**. A capless caller receives an empty list — not `PermissionDenied`.

**Signatures.**

```
ListRoles (parent="", cascade=false, page_size, page_token) → [Role…]
ListGroups(parent="", cascade=false, page_size, page_token) → [Group…]
```

- `parent` — the folder to browse: empty string = global/folder-less nodes only;
  otherwise a DNS-style dotted path (leaf-first, e.g. `team.demo`) or a UUID.
  Browsing a folder path the caller cannot see returns `NotFound` (existence-hiding).
- `cascade` — when `false` (the default) only nodes **directly homed in `parent`**
  are returned; when `true` the entire subtree is walked flat. Use `--cascade` to
  include roles or groups nested under sub-folders.
- `page_token` — opaque keyset cursor; reuse `parent` / `cascade` across pages.

**Visibility rule.** A caller sees a role if it satisfies at least one of:

1. **Manageable** — holds a management capability at the role's folder scope
   (e.g. `access:role:read` on the folder or an ancestor).
2. **Holds** — holds the role via a standing binding or an active JIT grant.
3. **Requestable** — is eligible to request the role via a request policy.

A caller sees a group if it satisfies at least one of:

1. **Manageable** — holds `identity:group:read` (or a broader cap) at the group's
   folder scope or an ancestor.
2. **Member** — is a direct or transitive member of the group.

**List vs. detail split.** `ListRoles`/`ListGroups` return navigation-only bare
nodes (id, name, folder path). The detail RPCs return the caller's **capabilities**
at the node's governing scope:

- `GetRoleAccess(role_id)` — returns the caller's management capabilities on the
  role's folder scope. Returns **`PermissionDenied`** (not `NotFound`) when the
  caller has no relationship to the role at all, because roles are not catalog
  topology and their existence is not hidden from all non-admins.
- `GetGroupAccess(group_id)` — returns the caller's management capabilities on the
  group's folder scope. A member with no management capabilities receives an **empty
  capability list** (not an error). Returns **`NotFound`** when the caller is neither
  a manager nor a member (existence-hiding: groups are catalog-adjacent topology).

### Folder-contents aggregator — `ListFolderContents`

`CatalogService.ListFolderContents(parent)` returns a **bounded per-kind slice** of
the folder's direct children across all four kinds in a single call:

```
ListFolderContents(parent) → {
  folders[], folders_has_more,
  assets[],  assets_has_more,
  roles[],   roles_has_more,
  groups[],  groups_has_more,
}
```

Each slice holds up to 50 items and applies the same visibility rule as the
per-kind list. When `<kind>_has_more` is `true`, use the corresponding
`List<Kind>(parent, cascade=false)` paginated browse to retrieve the rest. Useful
for overview panels and breadcrumb expansions where one round trip per folder is
preferable to four.

## Where enforcement lives (data plane) — warden decides, workers enforce

The control plane **brokers** and the data plane **enforces** (see
[architecture.md](architecture.md#the-three-planes)). Capabilities sit exactly on
that boundary, and the split is deliberate:

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

## Data-plane vocabulary

The protocol verbs a **worker** enforces at a live session (the management-plane
vocabulary is [above](#the-vocabulary)). `ssh:*` is enforced today by the ssh-proxy
worker; `db:*` / `k8s:*` are **defined for the model** and land with their proxies.
The exact per-protocol lists are settled when each worker is built — the grammar
and matcher are stable now, the protocol coverage grows.

| Capability | Meaning (worker-side) | Enforced by | Enforced today |
|---|---|---|---|
| `ssh:connect` | Open an SSH session to the target (the effective gate is `ssh:login:*`) | ssh-proxy | via `ssh:login:*` |
| `ssh:login:<account>` | Log in **as the OS account `<account>`** (`ssh:login:root`, `ssh:login:deploy`, or `ssh:login:*` for any configured login). **Drives the SSH cert principals** the [CredentialBroker](architecture.md#vault--credentialbroker) mints: `ValidPrincipals` are the host-scoped `<login>@<asset>` forms of the asset's configured logins ∩ the user's held `ssh:login:*` | broker + ssh-proxy | **Yes** — broker cert minting + ssh-proxy session gate |
| `ssh:record:exempt` | Exempt the subject from mandatory session recording on the asset (recording is otherwise fail-closed) | ssh-proxy (decided by warden at setup) | **Yes** |
| `db:connect` | Open a Postgres session | pg-proxy (planned) | No |
| `db:ddl` | Run a DDL statement (`CREATE`/`ALTER`/…) | pg-proxy (planned) | No |
| `db:read`, `db:write`, … | Finer per-statement tiers (`readonly`/`readwrite`/`ddl`); a role may bundle these or use the `db:*` glob | pg-proxy (planned) | No |
| `k8s:connect` | Reach the cluster API through the proxy | k8s-proxy (planned) | No |
| `k8s:access` | Impersonate **as the requesting user** | k8s-proxy (planned) | No |
| `k8s:impersonate:<role>` | Impersonate **as `<role>`** (e.g. `k8s:impersonate:cluster-admin`) | k8s-proxy (planned) | No |

## Related

- [access-model.md](access-model.md) — how roles bundle capabilities and how
  the ReBAC graph decides which roles a user holds.
- [architecture.md](architecture.md#the-three-planes) —
  the control-plane-brokers / worker-enforces split.
