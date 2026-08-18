# Data model

A reference for warden's Postgres schema — the core tables, their key columns,
and how they relate. Derived from the embedded migrations
(`warden/internal/db/migrate/migrations/0001..0005`). This is the storage behind
the concepts in [access-model.md](access-model.md); read that first for the
*meaning*, this for the *columns*.

The relationship rows are **tuple-shaped** (subject → relation → object), so the
whole model could be mirrored into an external relationship engine (OpenFGA)
without changing the domain — see [decisions.md](decisions.md).

## ER diagram

```
                group_memberships
                 (nested: member_user_id | member_group_id)
        ┌──────────────┴───────────────┐
      users                          groups
        │  ▲                          ▲  │
        │  │ subject_user_id          │  │ subject_group_id
        │  └──────────┐    ┌──────────┘  │
        │             role_bindings      │
        │             (kind, scope_*)    │
        │                │  ▲            │
   auth_tokens           │  │ role_id    │
   (user_id)             ▼  │            │
                        roles ◄──────── role_grants
                (capabilities jsonb)    (role_id, source_role_id,
                        │  ▲             via same_object|parent)
             role_id    │  │ role_id / approver_role_id
                        ▼  │
                 approval_rules ──── approval_rule_approvers
                 (scope_*, required   (subject_user_id | subject_group_id)
                  _approvals)

        folders ──parent_id──► folders          (forest / tree)
           ▲                      │
           │ folder_id           │ scope_folder_id (role_bindings,
           │                     │                  approval_rules)
        assets ◄─────────────────┘
     (folder_id, labels)   scope_asset_id (role_bindings, approval_rules)

        audit_log  (seq, prev_hash, entry_hash)   — append-only, hash-chained
```

`role_bindings` and `approval_rules` each reference **either** a folder **or** an
asset as their scope (CHECK-enforced XOR), and `role_bindings` /
`approval_rule_approvers` each reference **either** a user **or** a group as their
subject (XOR).

## Tables

### `users` — local accounts

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `email` | unique |
| `display_name` | |
| `password_hash` | argon2id (added in `0002`; default `''`) |
| `is_admin` | admin guard flag (added in `0002`) |

### `groups` — named subject sets

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `name` | unique |

### `group_memberships` — nested membership edges

A member is **either** a user **or** a group (XOR, `one_member`), which is what
makes groups **nested**. `no_self_member` blocks direct self-membership; unique
indexes prevent duplicate edges.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `group_id` | the containing group → `groups(id)` |
| `member_user_id` | member is a user → `users(id)` (nullable) |
| `member_group_id` | member is a group → `groups(id)` (nullable) |

### `folders` — resource tree

Self-referential via `parent_id` (a forest). `no_self_parent` blocks direct
`A→A`; the migration comment notes multi-node cycles are avoided only because
folders are created leaf-only today (a future reparent endpoint must enforce
acyclicity). The recursive CTEs (`HoldsRole` / `held` / `applicable`) assume this
forest shape.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `name` | |
| `parent_id` | → `folders(id)`, nullable (root folders) |

### `assets` — protected resources

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `folder_id` | → `folders(id)`, **NOT NULL** (every asset lives in exactly one folder) |
| `name` | |
| `labels` | jsonb (default `{}`), GIN-indexed |

### `roles` — capability bundles

Scoped to a resource type. `capabilities` is a **JSON array of capability
strings** (the vocabulary in [capabilities.md](capabilities.md)). `(name,
resource_type)` is unique.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `name` | |
| `resource_type` | CHECK in (`folder`, `asset`) |
| `capabilities` | jsonb array of capability patterns (default `[]`) |

### `role_bindings` — role → subject @ scope

Attaches a role to a subject at a scope, as one of two **kinds**. Two XOR CHECKs:
scope is folder **xor** asset (`one_scope`); subject is user **xor** group
(`one_subject`).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `role_id` | → `roles(id)` |
| `kind` | CHECK in (`standing`, `requestable`) |
| `scope_folder_id` | scope is a folder → `folders(id)` (nullable) |
| `scope_asset_id` | scope is an asset → `assets(id)` (nullable) |
| `subject_user_id` | subject is a user → `users(id)` (nullable) |
| `subject_group_id` | subject is a group → `groups(id)` (nullable) |

### `role_grants` — the ReBAC rewrite rules

`"holding source_role_id on the relevant object CONFERS role_id"`, resolved by
`HoldsRole`. `via` selects the axis. `(role_id, source_role_id, via)` is unique;
`no_self_same_object` blocks a trivial `R ⊇ R via same_object`.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `role_id` | the conferred role `R` → `roles(id)` |
| `source_role_id` | the source role `S` → `roles(id)` |
| `via` | CHECK in (`same_object`, `parent`) — composition vs folder cascade |

### `approval_rules` — approval policy per (role, scope)

Gates activation of a **requestable** role. Scope is **NULL** (the role-level
default) **or** exactly one of folder/asset (an override) — `scope_shape` CHECK.
Partial-unique indexes enforce one default and one override per (role, scope).
`approver_role_id` is the optional approver-role (`ON DELETE RESTRICT`).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `role_id` | the role being gated → `roles(id)` |
| `scope_folder_id` | override scope folder → `folders(id)` (nullable) |
| `scope_asset_id` | override scope asset → `assets(id)` (nullable) |
| `required_approvals` | int, CHECK ≥ 1 (the N-of-M threshold) |
| `approver_role_id` | "holders of this role on the scope may approve" → `roles(id)` (nullable) |

### `approval_rule_approvers` — explicit approver subjects

The **∪-explicit-subjects** half of an approval rule's approver set. Subject is
user **xor** group (`one_subject`).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `rule_id` | → `approval_rules(id)` |
| `subject_user_id` | → `users(id)` (nullable) |
| `subject_group_id` | → `groups(id)` (nullable) |

### `audit_log` — hash-chained append-only log

Tamper-evident: `entry_hash = sha256(prev_hash ‖ canonical(entry))`. `seq` is a
generated identity (monotonic ordering); both `seq` and `entry_hash` are unique.
See [architecture.md](architecture.md#audit--recording).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `seq` | bigint, GENERATED ALWAYS AS IDENTITY (chain order) |
| `event_type` | |
| `actor_user_id` | uuid, nullable (no FK — actors may be deleted) |
| `subject` | text (default `''`) |
| `details` | jsonb (default `{}`) |
| `prev_hash` | bytea — previous entry's `entry_hash` |
| `entry_hash` | bytea, unique — this entry's hash |

### `auth_tokens` — opaque bearer tokens

Login mints a random token; only its **hash** is stored. Instant server-side
revocation = delete the row. See
[security.md](security.md#authn--token-model).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `user_id` | → `users(id)` |
| `token_hash` | bytea, unique |
| `expires_at` | timestamptz |

## Related

- [access-model.md](access-model.md) — the conceptual model these tables encode.
- [capabilities.md](capabilities.md) — the format of `roles.capabilities`.
- [security.md](security.md) — the security posture, including audit and tokens.
