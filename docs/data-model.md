# Data model

A reference for warden's Postgres schema — the core tables, their key columns,
and how they relate. Derived from the embedded migrations
(`warden/internal/db/migrate/migrations/0001..0009`). This is the storage behind
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
   (deactivated_at)                     ▲  │
        │  ▲                          │  │ subject_group_id
        │  │ subject_user_id          │  │
        │  └──────────┐    ┌──────────┘  │
        │             role_bindings      │        (STANDING only)
        │             (scope_*)          │
        │                │  ▲            │
   auth_tokens           │  │ role_id    │
   (user_id)             ▼  │            │
                        roles ◄──────── role_grants
                (capabilities jsonb)    (role_id, source_role_id,
                        │  ▲             via same_object|parent)
             role_id /  │  │ role_id / approver_role_id /
             requester_ │  │ requester_role_id
             role_id    ▼  │
                request_policies ──── request_policy_subjects
                (scope_*, required     (kind ∈ {requester,approver};
                 _approvals,            subject_user_id | subject_group_id)
                 approver_role_id,
                 requester_role_id)

        folders ──parent_id──► folders          (forest / tree)
           ▲                      │
           │ folder_id           │ scope_folder_id (role_bindings,
           │                     │                  request_policies)
        assets ◄─────────────────┘
     (folder_id, kind,     scope_asset_id (role_bindings, request_policies)
      labels)  │
               │ asset_id
        ┌──────┴───────┐                       ca_keys  (kind ssh|x509,
   asset_secrets   ssh_asset_config             sealed, public_material,
   (name, sealed)  (allowed_logins[],           active — one active per kind)
        ▲           auth_method, ────────┐      — the M3d vault (sealed at rest)
        └───────────stored_secret_id ────┘

        audit_log  (seq, prev_hash, entry_hash)   — append-only, hash-chained

        access_requests ──┐ (requester_user_id, role_id, asset_id,
         (status pending  │  required_approvals + granted_duration SNAPSHOTS)
          →granted|denied │
          |cancelled)     ├── access_request_approvals
                          │     (approver_user_id, decision approve|deny,
                          │      UNIQUE per approver)
                          └── access_grants
                                (role_id, scope_asset_id, subject_user_id,
                                 expires_at, revoked_at/by/reason;
                                 active ⇔ revoked_at IS NULL AND expires_at > now())
```

The JIT-runtime tables (`access_requests` → `access_request_approvals` /
`access_grants`) reference `users`, `roles`, and `assets`; a live `access_grant`
joins the authorizer's standing set (see below and
[access-model.md](access-model.md#standing-access--what-can-i-do-right-now)).

`role_bindings` and `request_policies` each reference **either** a folder **or** an
asset as their scope (CHECK-enforced XOR; `request_policies` also allows
NULL/NULL = the role-level default), and `role_bindings` /
`request_policy_subjects` each reference **either** a user **or** a group as their
subject (XOR).

## Tables

### `users` — local accounts

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `email` | unique |
| `display_name` | |
| `password_hash` | argon2id (added in `0002`; default `''`) |
| `deactivated_at` | timestamptz, nullable (added in `0006`); **NULL = active**. Non-NULL ⇒ the account is rejected at Login and at the auth interceptor. See [security.md](security.md#account-deactivation). |

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
acyclicity). The recursive CTEs (`HoldsRole` / `held` / the requestable-policy
ancestor walk) assume this forest shape.

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
| `kind` | text, **NOT NULL DEFAULT `'ssh'`**, CHECK in (`ssh`, `postgres`, `k8s`) (added `0009`). Selects the asset's **typed credential config** (the vault) — `ssh` → `ssh_asset_config`; `postgres`/`k8s` configs are M5. `assets` stays the generic authz anchor (roles/bindings/grants/policies reference `assets.id` protocol-agnostically); `kind` only drives the [vault](architecture.md#vault--credentialbroker-m3d). |
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

### `role_bindings` — role → subject @ scope (standing-only)

Attaches a role to a subject at a scope. A binding is **standing-only** —
permanent, admin-granted access; the `kind` column was **dropped in `0007`**
(requestability now comes from `request_policies`, not a binding). Two XOR CHECKs:
scope is folder **xor** asset (`one_scope`); subject is user **xor** group
(`one_subject`).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `role_id` | → `roles(id)` |
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

### `request_policies` — requestability + approval policy per (role, scope)

Renamed from `approval_rules` in `0006` (+ `requester_role_id`). **One row per
(role, scope) makes that role requestable on that scope** — its existence *is* the
requestability, and it carries both the requester side (who may ask) and the
approval side (who signs off). Scope is **NULL** (the role-level default) **or**
exactly one of folder/asset (an override) — `scope_shape` CHECK. Partial-unique
indexes enforce one default and one override per (role, scope). `approver_role_id`
and `requester_role_id` are both `ON DELETE RESTRICT`.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `role_id` | the requestable role → `roles(id)` (`ON DELETE CASCADE`) |
| `scope_folder_id` | override scope folder → `folders(id)` (nullable) |
| `scope_asset_id` | override scope asset → `assets(id)` (nullable); both NULL = role-level default |
| `required_approvals` | int, **CHECK ≥ 0** (the N-of-M threshold; relaxed from `≥ 1` in `0008`). `0` = **self-service**: an eligible requester is auto-granted, no approver needed (`CreateRequestPolicy`/`UpdateRequestPolicy` validation is now `gte: 0`). |
| `approver_role_id` | "holders of this role on the scope may approve" → `roles(id)` (nullable, `ON DELETE RESTRICT`) |
| `requester_role_id` | "holders of this role on the scope may request" → `roles(id)` (nullable, `ON DELETE RESTRICT`; added `0006`). A NULL requester-role is **not** "anyone". |
| `max_duration` | interval, **nullable** (added `0008`); per-policy ceiling on a granted duration. NULL ⇒ fall back to the global `MaxGrantTTL` cap. |

### `request_policy_subjects` — explicit requester/approver subjects

Renamed from `approval_rule_approvers` in `0006` (+ `kind`). Unifies the
explicit-subject half of both the requester set and the approver set, distinguished
by `kind`. Subject is user **xor** group (`one_subject`).

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `policy_id` | → `request_policies(id)` (renamed from `rule_id` in `0006`, `ON DELETE CASCADE`) |
| `kind` | CHECK in (`requester`, `approver`) — which side this subject is on (added `0006`) |
| `subject_user_id` | → `users(id)` (nullable) |
| `subject_group_id` | → `groups(id)` (nullable) |

### `access_requests` — JIT access requests (M3c)

A user's request to activate a **requestable** role on an **asset** (asset-scoped
only in M3c). Added in `0008`. `required_approvals` and `granted_duration` are
**snapshots** taken at request time (`required_approvals` from the effective
policy; `granted_duration` = the clamped duration `min(requested,
policy.max_duration, global MaxGrantTTL)`) so a mid-flight policy edit cannot
change an in-progress request. A **partial-unique index**
(`uq_pending_request` on `(requester_user_id, role_id, asset_id) WHERE status =
'pending'`) blocks a second pending request for the same tuple.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `requester_user_id` | → `users(id)` (`ON DELETE CASCADE`) |
| `role_id` | requested role → `roles(id)` (`ON DELETE CASCADE`) |
| `asset_id` | requested scope asset → `assets(id)` (`ON DELETE CASCADE`) |
| `reason` | text (default `''`) — free-form justification |
| `requested_duration` | interval — what the requester asked for |
| `required_approvals` | int — **snapshot** of the effective policy's N-of-M threshold |
| `granted_duration` | interval — **snapshot** of the clamped grant lifetime |
| `status` | CHECK in (`pending`, `granted`, `denied`, `cancelled`); default `pending` |
| `created_at` | timestamptz (default `now()`) |
| `resolved_at` | timestamptz, nullable (set when it leaves `pending`) |

### `access_request_approvals` — per-approver decisions (M3c)

One row per approver decision on a request. `UNIQUE (request_id,
approver_user_id)` enforces **one decision per approver** (blocks double-voting).
A single `deny` rejects the request; the N-th distinct `approve` mints the grant.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `request_id` | → `access_requests(id)` (`ON DELETE CASCADE`) |
| `approver_user_id` | → `users(id)` (`ON DELETE CASCADE`) |
| `decision` | CHECK in (`approve`, `deny`) |
| `created_at` | timestamptz (default `now()`) |

### `access_grants` — time-boxed JIT grants (M3c)

Written when a request is granted (self-service at `required_approvals = 0`, or on
reaching the approval threshold). Always to a **user** (the requester) at an
**asset** scope, with a denormalized `role_id`/`scope_asset_id` so the grant joins
the authorizer directly. `UNIQUE (request_id)` means **a request yields at most one
grant**. A grant is **active** iff `revoked_at IS NULL AND expires_at > now()`; the
authorizer's held-closure base becomes `role_bindings ∪ active access_grants`, so a
live grant flows through the role-rewrite graph exactly like a standing binding and
stops conferring the instant it expires or is revoked. Warden owns the record;
runtime never mutates admin config (`role_bindings`). A partial index
(`idx_access_grants_active` on `subject_user_id WHERE revoked_at IS NULL`) serves
the active-grant lookups.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `request_id` | → `access_requests(id)` (`ON DELETE CASCADE`); UNIQUE |
| `role_id` | granted role (denormalized for the authz union) → `roles(id)` (`ON DELETE CASCADE`) |
| `scope_asset_id` | granted scope asset → `assets(id)` (`ON DELETE CASCADE`) |
| `subject_user_id` | grantee (the requester) → `users(id)` (`ON DELETE CASCADE`) |
| `granted_at` | timestamptz (default `now()`) |
| `expires_at` | timestamptz **NOT NULL** — end of the grant window |
| `revoked_at` | timestamptz, nullable — set on manual revoke, deactivation, or expiry |
| `revoked_by` | → `users(id)` (`ON DELETE SET NULL`); **NULL actor = reaper/system** (expiry) |
| `revoked_reason` | text, nullable (`expired`, `user_deactivated`, or a caller reason) |

See [access-model.md](access-model.md#approval--who-signs-off-and-how-a-request-activates-m3c-workflow)
for the request→approve→grant workflow and
[security.md](security.md#continuous-enforcement--revocation-tears-down-live-sessions)
for the revocation matrix.

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

## Vault tables (M3d)

The credential vault (migration `0009`). All `sealed bytea` columns hold
**envelope-encrypted** material (a per-secret AES-256-GCM DEK wrapped by the
master KEK — see [architecture.md](architecture.md#vault--credentialbroker-m3d)
and [security.md](security.md#secrets-at-rest)); the plaintext **never** touches
the DB and the sealed bytes are **never** returned via the API (`ListAssetSecrets`
is metadata-only). See [access-model.md](access-model.md#ssh-access--os-logins-are-capabilities-m3d).

### `ca_keys` — certificate-authority key material (M3d)

Global CA singletons, sealed at rest. At most **one active per kind** (partial
unique index `uq_active_ca` on `(kind) WHERE active`) — the `active` flag leaves
room for later rotation. Created by `VaultService.InitCA(kind)`.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `kind` | text, CHECK in (`ssh`, `x509`) — SSH user CA (ed25519) or X.509 client CA (ECDSA P-256) |
| `sealed` | bytea **NOT NULL** — `Seal`ed CA private material (SSH: 32-byte ed25519 seed; X.509: PKCS#8 key DER). Never returned via the API |
| `public_material` | text **NOT NULL** — the distributable public half (SSH: the `authorized_keys` CA line hosts add to `TrustedUserCAKeys`; X.509: the CA cert PEM). Returned by `GetCAPublic` |
| `created_at` | timestamptz (default `now()`) |
| `active` | boolean **NOT NULL DEFAULT true** — one active per kind (partial unique index) |

### `asset_secrets` — per-asset stored secrets (M3d)

Named secrets bound to an asset (e.g. a stored SSH private key / password), sealed
at rest. `UNIQUE (asset_id, name)`; `SetAssetSecret` upserts by `(asset_id,
name)`. Values leave warden **only** via the broker (opened for a live credential);
`ListAssetSecrets` returns id/name/created_at metadata only.

| Column | Notes |
|---|---|
| `id` | uuid PK |
| `asset_id` | → `assets(id)` (`ON DELETE CASCADE`) |
| `name` | text **NOT NULL** |
| `sealed` | bytea **NOT NULL** — `Seal`ed secret value. Never returned via the API |
| `created_at` | timestamptz (default `now()`) |

### `ssh_asset_config` — the SSH kind's typed credential config (M3d)

1:1 with an `ssh` asset (`asset_id` is the PK). Describes how the broker mints an
SSH credential: the host's OS-account allowlist and the auth method.

| Column | Notes |
|---|---|
| `asset_id` | uuid **PK** → `assets(id)` (`ON DELETE CASCADE`) — 1:1 with the asset |
| `allowed_logins` | `text[]` **NOT NULL** — the OS accounts that exist on the host (the allowlist). The broker's cert principals are this list **∩** the user's `ssh:login:*` capabilities — see [access-model.md](access-model.md#ssh-access--os-logins-are-capabilities-m3d) |
| `auth_method` | text **NOT NULL**, CHECK in (`ca-cert`, `stored-key`) — mint a short-lived SSH cert via the SSH CA, or return a stored key |
| `stored_secret_id` | → `asset_secrets(id)` (`ON DELETE RESTRICT`), nullable. **Required iff** `auth_method='stored-key'` (CHECK `stored_key_needs_secret`) |

> `postgres_asset_config` / `k8s_asset_config` (the typed configs for the other
> `assets.kind` values) land in **M5**, alongside their proxies.

## Related

- [access-model.md](access-model.md) — the conceptual model these tables encode.
- [capabilities.md](capabilities.md) — the format of `roles.capabilities`.
- [security.md](security.md) — the security posture, including audit and tokens.
