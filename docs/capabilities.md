# Capabilities

A capability is the primitive verb a role grants. It names what a subject may do:
either a data-plane action on an asset (open an SSH session, log in to a Postgres
role, act as a Kubernetes group, log in to an RDP host) or a management-plane action
on the API (onboard an asset, create a role, bind it, manage users). Roles bundle
capabilities, and the authorizer answers one question: does this user hold a role,
at the relevant scope, whose capabilities cover the requested action?

The same grammar, format validation, and glob matcher serve both halves. They differ
only in where they are enforced (worker versus warden) and at what scope they are
checked.

- Management plane — enforced by warden. Every management RPC (catalog, access,
  identity, vault, recording admin) is gated by a capability check in the handler
  (`requireCap`). This replaced the old boolean `is_admin` gate; see
  [Management-plane capabilities](#management-plane-capabilities).
- Data plane — enforced by the workers. The ssh-proxy enforces `ssh:*` at a live
  session, the pg-proxy enforces `db:login:*`, the rdp-proxy enforces `rdp:login:*`,
  and the k8s-broker projects `k8s:group:*` into impersonation. See
  [Data-plane vocabulary](#data-plane-vocabulary).

## Grammar

A capability is a colon-delimited path of segments:

```
scope:action[:qualifier…]
```

- It is always scoped, with at least two segments (`ssh:connect`, not `connect`). A
  bare `admin` is rejected.
- Each segment is lowercase alphanumeric with internal hyphens
  (`[a-z0-9]+(-[a-z0-9]+)*`, for example `cluster-admin`). No uppercase, no
  leading, trailing, or empty segments.
- The first segment is the scope (the protocol or subsystem: `ssh`, `db`, `k8s`),
  the second is the action, and any further segments are qualifiers
  (`k8s:group:system:masters`).

The format is validated at `CreateRole` by protovalidate (a regex in
[`catalog.proto`](../proto/jumpgate/catalog/v1/catalog.proto), on the
`CreateRoleRequest.capabilities` field). Invalid strings are rejected with
`InvalidArgument` before the role is stored.

| Rejected | Why |
|---|---|
| `admin` | unscoped (only one segment) |
| `*` | unscoped |
| `k8s:` | empty trailing segment |
| `k8s:**:x` | `**` is not the final segment |
| `DROP TABLE` | space and uppercase — not a valid segment |
| `K8s:connect` | uppercase |

### Storage

A capability is stored decomposed into segments, not as a string. Each pattern on a
role becomes one `role_capabilities(role_id, scope, action, qualifier)` row: `ssh:login:root`
stores `(ssh, login, root)`, `db:read` stores `(db, read, '')`, and a multi-segment
qualifier keeps its tail intact so `k8s:group:system:masters` stores
`(k8s, group, system:masters)`. A btree index on `(scope, action, qualifier)` makes
the match a keyed lookup. See [data-model.md](data-model.md#role_capabilities--decomposed-capability-patterns).

The one bare-wildcard exception is `**`. A standalone `**` is a valid stored pattern
that matches every capability at any depth. It is the `admin` role's only capability:
the bootstrap admin is an ordinary user holding a role whose capabilities are `["**"]`,
bound globally. (`**` is still rejected as a middle segment, and a bare `*` or `admin`
is still rejected.)

## Glob patterns

A role's stored capability list may contain glob patterns. The requested capability
at check-time is always concrete — a worker asks about a specific operation, never a
wildcard. Two wildcards exist:

- `*` matches exactly one segment. It never crosses a `:`.
- A trailing `**` matches one or more remaining segments, and may appear only as the
  final segment.

The glob semantics live in one auditable function,
[`CapMatch(pattern, requested)`](../warden/internal/authz/capabilities.go). `Check`
unions the capability sets of all roles the user holds on the asset and returns true
if any stored pattern `CapMatch`es the requested capability. The everyday hot path
runs the equivalent match as a three-column SQL predicate over `role_capabilities`,
proven identical to the Go function by `TestSQLCapMatchMatchesGo`, so the indexed
lookup and the reference semantics never drift.

| Pattern | Matches | Does NOT match |
|---|---|---|
| `k8s:*` | `k8s:connect`, `k8s:access` | `k8s:group:developers` (three-segment) |
| `k8s:*:*` | `k8s:group:developers` | `k8s:connect` |
| `k8s:group:*` | `k8s:group:developers` | `k8s:connect` |
| `k8s:**` | all `k8s` caps, any depth | `k8s` (needs at least one segment after) |
| `*:connect` | `ssh:connect`, `db:connect` | `ssh:access` |
| `db:read` (concrete) | `db:read` only | `db:read:foo` |

### Safety properties

- `*` is exactly one segment and never crosses a `:`, so `k8s:*` cannot reach into
  `k8s:group:developers`. Widening one level requires writing `*` at each level
  (`k8s:*:*`).
- A concrete pattern never matches deeper: `db:read` grants `db:read` and nothing
  under it.
- `**` is the explicit, auditable "this whole scope, at any depth" grant. Someone
  reading a role's capability list sees `k8s:**` and knows it is broad, so breadth is
  never accidental.
- `CapMatch` fails closed on a malformed non-final `**` (`k8s:**:x`): rather than
  silently dropping the segments after `**`, which would over-match, it returns
  false. The proto grammar already rejects such patterns at `CreateRole`; `CapMatch`
  enforces the same invariant defensively, so a pattern reaching it via a non-proto
  path can never match more than its literal segments intend.

### Matching versus enumeration

Two different questions run over the same stored patterns, and they treat wildcards
differently. This distinction is load-bearing for Kubernetes.

- Matching (`Check` / `CapMatch`) asks "does any held pattern cover this concrete
  request?" Wildcards match, so `**` covers everything and `ssh:login:*` covers
  `ssh:login:root`.
- Enumeration (`ConcreteQualifiers(prefix)`) asks "which concrete qualifiers does the
  user hold under this prefix?" It returns only literal values and skips any pattern
  containing a wildcard.

SSH logins use matching: an asset defines a finite set of logins, and the broker
intersects that set with the user's held `ssh:login:*` capabilities, so `ssh:login:*`
grants every configured login. Kubernetes groups use enumeration: there is no finite
group set to intersect against, so the broker enumerates the concrete
`k8s:group:<name>` qualifiers the user holds and projects each as an impersonated
group. A wildcard cannot be enumerated, so `k8s:group:*` and `**` yield no groups —
an intended safety property, covered under [Data-plane vocabulary](#data-plane-vocabulary).

## Management-plane capabilities

The management API (creating folders, assets, roles, bindings, and policies; managing
users and groups; vault CAs and secrets; reading recordings) is governed by
capabilities too, but here warden both decides and enforces them directly in the RPC
handler, with no worker in the loop.

### Scope — global / folder / asset

A management capability is checked at a scope, not just "on an asset":

- global — system-wide operations (create a user, a top-level folder, a global role;
  CA init). A capability is held globally via a scopeless role binding (a
  `role_binding` with neither `scope_folder_id` nor `scope_asset_id`).
- folder — operations within a folder subtree (onboard an asset in `prod`, manage
  roles, bindings, and policies there). A folder-scoped binding confers the cap.
- asset — operations on one asset (update its config, write its stored secret).

`CapabilitiesOnScope(user, scope)` returns the caps the user holds there:
globally-held caps plus, for a folder or asset scope, caps held on the object and
every ancestor folder. Management authority therefore cascades down the folder tree:
a cap granted at `prod` applies to `prod`, its sub-folders, and all their assets, with
no extra wiring. (This folder cascade is management-specific; it does not use the
data-plane held-closure's opt-in `parent` role-grants.) `requireCap(cap, scope)` in
each handler is `CapabilitiesOnScope(...).Allows(cap)`, else `PermissionDenied`. The
admin's global `**` satisfies every check.

### No-escalation subset rule

Binding a role, making it requestable, or wiring the role-grant graph grants that
role's capabilities, so it is guarded: a caller may bind or grant role `R` at scope
`S` only if every capability in `R` is subsumed by what the caller holds at `S`
(`requireGrantable` → `Covers` pattern-subsumption). No one can grant authority they
do not have. The admin (`**`) can grant anything; a `prod`-admin holding
`catalog:**`, `access:**`, and `ssh:login:*` on `prod` can grant up to that within
`prod`, but cannot grant `identity:*` or bind a global `admin` role. This applies at
`CreateRoleBinding`, `CreateRequestPolicy`, and `AddRoleGrant` — the last checks the
recipient `role_id`, the role that gets conferred.

### The vocabulary

The management vocabulary is `<service>:<resource>:<verb>`, with the same grammar and
globs as everything else. Every check runs at one scope: `Global`, a folder, or an
asset. Three rules hold everywhere, so the table stays terse:

- Cascade. A folder check is satisfied by the cap held on that folder, on any
  ancestor folder, or globally.
- No folder home means `Global`. An object with no `folder_id` (a global role or
  group) is checked at `Global`.
- List-all means `Global`. Endpoints that scan the whole table (`ListRoleBindings`,
  `ListRequestPolicies`, `ListUsers`) require the read cap at `Global`; the per-object
  `Get`/`Resolve` forms use the object's own scope. `ListRoles`, `ListGroups`,
  `ListFolders`, and `ListAssets` are exceptions: they are visibility-filtered path
  browses (see [Browse endpoints](#browse-endpoints)) and require no global read cap.

`catalog:folder:read` cascades read across a whole subtree. Held on a folder `F`, it
confers read and visibility of everything homed at or under `F` — descendant
sub-folders and the assets, roles, and groups within — so a delegate governing a
folder branch can browse and open its contents without also holding
`catalog:asset:read`, `access:role:read`, and `identity:group:read` object by object.
It is the one cross-object read cap; every other read cap stays object-type-specific.
`catalog:folder:read` is read-only: it grants no authoring, no connect (a data-plane
entitlement such as `ssh:login:*` is still required to open a session), and it is
deliberately excluded from the no-escalation subset rule, so holding it can never let
a delegate bind or grant an object read cap they do not themselves hold.

The Scope column names the object whose scope the cap is checked at. Where a single
cap gates both a per-object read and a list-all, the list case is noted in
parentheses.

| Capability | Grants (management RPC) | Scope |
|---|---|---|
| `catalog:folder:create` | create a folder | parent folder (`Global` if top-level) |
| `catalog:folder:read` | resolve a folder by path/id; read everything in the folder's subtree (descendant sub-folders, assets, roles, groups) | the folder |
| `catalog:folder:update` | rename or move a folder | the folder |
| `catalog:folder:delete` | delete a folder | the folder |
| `catalog:asset:create` | onboard an asset (SSH, Postgres, Kubernetes, or RDP) | target folder |
| `catalog:asset:read` | get or resolve an asset | the asset |
| `catalog:asset:update` | change an asset's config; re-mint a Kubernetes enrollment token | the asset |
| `catalog:asset:delete` | delete an asset | the asset |
| `access:role:create` | create a role | target folder (`Global` if a global role) |
| `access:role:read` | get or resolve a role; list a role's grants; explain a role | the role's folder |
| `access:role:update` | add or remove role-rewrite grants (`role_grants`) | the role's folder |
| `access:binding:create` | bind a role to a subject (plus subset rule) | the binding's scope |
| `access:binding:read` | list role bindings | `Global` |
| `access:binding:delete` | remove a binding | the binding's scope |
| `access:policy:create` | create a request policy (plus subset rule) | the policy's scope |
| `access:policy:read` | get a policy; list subjects; check approval eligibility; list policies | the policy's scope (approval-check: the asset; list-all: `Global`) |
| `access:policy:update` | update a request policy | the policy's scope |
| `access:policy:delete` | delete a request policy | the policy's scope |
| `access:policy:manage-subjects` | add or remove requester and approver subjects | the policy's scope |
| `access:grant:read` † | list all JIT access grants (oversight) | `Global` |
| `access:grant:revoke` † | revoke a grant outside your approver scope (oversight) | `Global` |
| `identity:user:create` | create a user | `Global` |
| `identity:user:read` | get, resolve, or list users | `Global` |
| `identity:user:deactivate` | deactivate or reactivate a user | `Global` |
| `identity:user:delete` | delete a user | `Global` |
| `identity:group:create` | create a group | target folder (`Global` if a global group) |
| `identity:group:read` | resolve a group; list its members | the group's folder |
| `identity:group:add-member` | add a user or group to a group | the group's folder |
| `identity:group:remove-member` | remove a member | the group's folder |
| `identity:group:delete` | delete a group | the group's folder |
| `vault:ca:init` | initialize the SSH, mesh, or X.509 CA | `Global` |
| `vault:ca:issue` | issue a mesh certificate | `Global` |
| `vault:ca:read` | read a CA public key | `Global` |
| `vault:key:init` | initialize the session key | `Global` |
| `vault:secret:write` | set or delete an asset's stored secret | the asset |
| `vault:secret:read` | list an asset's secrets | the asset |
| `recording:read` | list, fetch, or download session recordings | the recording's asset (unfiltered list: `Global`) |
| `**` | everything (the `admin` role) | any |

> Moving a folder or asset requires `…:update` on the moved node and `…:create` on
> the destination folder. A rename needs only `…:update` on the node itself.

> † `access:grant:*` is the cross-user oversight surface only. Every user sees and
> acts on their own just-in-time access with no capability required: `ListMyRequests`
> and `ListMyGrants` return the caller's own requests and grants, `ListPendingApprovals`
> returns the requests the caller is an eligible approver for, and a user may always
> revoke their own grant. A standing approver for a grant's `(role, scope)` may also
> revoke that grant, since the same eligibility that lets them approve the request
> lets them revoke the resulting access. Requesting access is governed by the request
> policy, not a management capability. `access:grant:read` and `access:grant:revoke`
> gate only the org-wide oversight view.

> A delegated folder-admin holds only the caps they were granted, so client-side
> name and path resolution (itself `*:read`-gated) may be unavailable for objects they
> cannot read; they address such objects by id. Widening a delegate's read caps
> restores name-based use.

Groups are folder-governed. Like roles, a group can be homed in a folder
(`groups.folder_id`) for governance only: it sets who may administer the group, and
does not affect membership or what the group is bound to. `identity:group:*` is
checked at the group's folder scope and cascades down the tree, so
`identity:group:create` on `team-a` delegates creating and managing groups under
`team-a`. Groups are addressed as `<group>@<folder-path>` (for example `sre@team.demo`),
with `@` distinguishing them from a role's `<role>.<folder-path>`. Membership,
including group-in-group nesting, is a separate axis and is not folder-scoped.
`identity:user:*` stays global, since users are not folder-homed.

Deferred: per-group owner delegation (a `scope_group_id` binding scope), folder-homing
users, and a subset guard on membership-adds.

### Browse endpoints

Four list RPCs are visibility-filtered rather than cap-gated: `ListFolders`,
`ListAssets`, `ListRoles`, and `ListGroups`. A capless caller receives an empty list,
not `PermissionDenied`. Browsing a folder path the caller cannot see returns
`NotFound` (existence-hiding).

Each takes an optional `parent` (empty for the root or global view; otherwise a
DNS-style dotted path or a UUID) and a `cascade` flag. With `cascade=false` (the
default) only the direct children of `parent` are returned; with `cascade=true` the
whole subtree is walked flat. Results page via an opaque keyset `page_token`.

Visibility is per node. A caller sees a node when it satisfies at least one of:

1. Manageable — the caller holds a management capability at that node's scope.
2. Active or Requestable — the caller holds a standing role that covers the node
   (or, for a role, holds it via a binding or grant), or is eligible to request one
   via a request policy. A group is also visible to its direct or transitive members.

The lists return navigation-only nodes (id, name, path). Per-node capabilities come
from the detail RPCs: `GetAssetAccess` and `GetFolderAccess` for the catalog,
`GetRoleAccess` and `GetGroupAccess` for roles and groups. `CatalogService.ListFolderContents`
returns a bounded per-kind preview (up to 50 folders, assets, roles, and groups) in
one call, with `<kind>_has_more` flags; callers needing the full list of a kind use
the per-kind browse.

## Where enforcement lives — warden decides, workers enforce

The control plane brokers and the data plane enforces (see
[architecture.md](architecture.md#the-three-planes)). Capabilities sit exactly on
that boundary, and the split is deliberate.

### warden (control plane) decides

To warden, capability strings are opaque tokens. It does not know that `db:ddl` means
"run a `CREATE TABLE`" or that a particular `k8s:group` grants god-mode on a cluster.
Given `(user, asset, capability)`, warden:

1. resolves which roles the user holds on the asset via the ReBAC graph — nested
   groups, standing `role_bindings`, and the `same_object` and `parent` rewrite rules
   in `role_grants` (`HoldsRole`, or its forward-closure dual `heldCTE`; see
   [access-model.md](access-model.md#role-inheritance)),
2. unions the capability sets of those held roles,
3. answers `Check` — true if some stored pattern `CapMatch`es the requested
   capability.

In one line: warden translates roles-in-scope into the set of held capabilities and
then into yes or no. It never interprets the meaning of a capability.

### workers / proxies (data plane) enforce

The proxy owns the semantics and the actual enforcement. For a live session it:

1. maps a concrete protocol operation to a capability — opening a shell is
   `ssh:connect`, logging in to a Postgres role is `db:login:<role>`, logging in to
   an RDP host is `rdp:login:<login>`, acting in a cluster is a `k8s:group:<name>`
   membership,
2. checks it against warden (`Check`, or a warden-issued short-lived decision or
   credential minted at session start),
3. allows or denies, and configures the access — injects the credential, sets the
   Kubernetes impersonation headers, and so on.

## Data-plane vocabulary

These are the protocol verbs a worker enforces at a live session. `ssh:*`, `db:*`,
`rdp:*`, and `k8s:*` are all enforced today. The exact per-protocol lists grow as
each worker gains features; the grammar and matcher are stable now.

| Capability | Meaning (worker-side) | Enforced by | Live today |
|---|---|---|---|
| `ssh:connect` | open an SSH session to the target (the effective gate is `ssh:login:*`) | ssh-proxy | yes, via `ssh:login:*` |
| `ssh:login:<account>` | log in as the OS account `<account>` (`ssh:login:root`, `ssh:login:deploy`, or `ssh:login:*` for any configured login). Drives the SSH cert principals the broker mints: the asset's configured logins intersected with the user's held `ssh:login:*` | broker + ssh-proxy | yes |
| `ssh:record:exempt` | exempt the subject from mandatory SSH session recording on the asset (recording is otherwise fail-closed) | ssh-proxy (decided by warden at setup) | yes |
| `db:login:<role>` | log in to the Postgres asset as DB role `<role>`. Holding it is the connect gate; the broker mints an X.509 client cert or returns the stored password for that role | broker + pg-proxy | yes |
| `db:read`, `db:write`, `db:ddl` | finer per-statement tiers for inline step-up. Defined for the model; per-statement enforcement (`SET ROLE`) is not built | pg-proxy | no (planned) |
| `rdp:login:<login>` | log in to the RDP asset as target account `<login>` (`rdp:login:demo`, or `rdp:login:*` for any configured login). Same mechanism as `ssh:login:<account>`: the asset's configured logins intersected with the user's held `rdp:login:*`; the broker returns the stored password for that login | broker + rdp-proxy | yes |
| `k8s:group:<name>` | act in the target cluster as the Kubernetes group `<name>`. Projected verbatim as an `Impersonate-Group` header; the cluster's own RBAC decides what the group may do | k8s-broker + agent | yes |

### Kubernetes: holding a group is the gate, and `**` is not cluster-admin

Kubernetes has exactly one capability, `k8s:group:<name>`, and it works differently
from SSH, Postgres, and RDP logins. There is no `k8s:connect` and no
`k8s:impersonate`.

- The connect gate is implicit. `CreateKubernetesSession` enumerates the caller's
  concrete `k8s:group:<name>` qualifiers; holding at least one is access, and holding
  none returns `NotFound`.
- Impersonation authority lives in the cluster, not in jumpgate. The broker sets one
  `Impersonate-Group` header per enumerated group. What each group can do is decided
  by the target cluster's RBAC, and by the agent ServiceAccount's own `impersonate`
  permissions.
- Because groups are enumerated, not matched (see
  [Matching versus enumeration](#matching-versus-enumeration)), wildcards grant
  nothing. `k8s:group:*` and the admin `**` both enumerate to zero groups, so a
  jumpgate admin holding `**` has no Kubernetes access. Cluster-admin requires an
  explicit concrete grant, for example `k8s:group:system:masters`, and a matching
  RBAC binding in the target cluster. Breadth in a cluster is therefore never
  conferred by a jumpgate wildcard.

## Related

- [access-model.md](access-model.md) — how roles bundle capabilities and how the
  ReBAC graph decides which roles a user holds.
- [architecture.md](architecture.md#the-three-planes) — the control-plane-brokers /
  worker-enforces split.
