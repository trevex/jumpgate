# Development

## Prerequisites

- [Nix](https://nixos.org/download) with flakes enabled.
- [direnv](https://direnv.net) (recommended) to auto-enter the devshell.

Everything else — Go, Rust, buf, protobuf, golangci-lint, Postgres, helm, kind,
cert-manager tooling, and an S3-compatible object store — is provided by the Nix
devshell. Do not install toolchains globally.

## Entering the devshell

```sh
direnv allow        # once; then the shell auto-enters on cd
# or, without direnv:
nix develop
```

The devshell pins:

- **Go** to the `warden/go.mod` minor's latest patch (via `go-overlay`).
- **Rust** to the channel in `rust-toolchain.toml` (stable), through `rustup`.
- Codegen and infra tooling at the versions locked in `flake.lock`.

Pre-commit hooks (rustfmt, clippy `-D warnings`, gofmt, golangci-lint) are wired
by `git-hooks.nix` and installed on devshell entry. Because the hooks call
`cargo`/`go`, **commit from inside the devshell** (`nix develop -c git commit …`
or with direnv active) or the hooks fail to find the toolchain.

## Common tasks (Makefile)

Run inside the devshell:

| Command | Does |
|---------|------|
| `make gen` | Generate protobuf stubs (`buf generate`) |
| `make build` | Build Go + Rust workspaces |
| `make test` | Run Go + Rust tests |
| `make lint` | gofmt + golangci-lint + rustfmt + clippy |
| `make fmt` | Auto-format Go + Rust |
| `make web` | Install, typecheck (`tsc --noEmit`), and build the SPA |
| `make ci` | Full pipeline: gen → build → test → lint → web (what CI runs) |
| `make ui-dev` | Start the UI dev stack (process-compose: Postgres + silo + warden + Vite) |
| `make ui-dev-reset` | Wipe local dev data (`.devdata/`); full re-provision on next `ui-dev` |
| `make ui-e2e` | Bring up kind (warden serves the embedded SPA) and run Playwright (opt-in) |

CI (`.github/workflows/ci.yml`) simply runs `nix develop -c make ci`, so local and
CI behavior are identical.

## Repository layout

```
warden/             Go   — API, identity, authz, vault, JIT/approvals, audit, data-plane control
gateway/            Rust — session router / load balancer (only exposed component)
workers/            Rust — per-protocol proxies (ssh-proxy; pg/k8s/rdp planned)
cli/                Go   — `jumpgate` CLI
web/                     — web SPA (Vite + React + TS), embedded in warden under -tags embedui
proto/              Shared gRPC/protobuf contracts (buf)
deploy/helm/        Helm chart (kind + cert-manager)
test/               End-to-end suite (test/e2e) and the kind test environment (test/env)
docs/               This documentation
flake.nix .envrc    Nix devshell + direnv
rust-toolchain.toml Pinned Rust toolchain
go.work             Go workspace (warden, cli, test/e2e)
Cargo.toml Cargo.lock Rust workspace
Makefile            Task entrypoints
```

## Module & package conventions

- **Go module path:** `github.com/trevex/jumpgate/warden` (matches the repo
  URL). Additional Go modules (e.g. `cli`) are added to `go.work`.
- **Go commands:** executable entrypoints live under `warden/cmd/`; the primary
  daemon is `warden/cmd/warden`. Process lifecycle and dependency wiring live in
  `warden/internal/app`, keeping command packages limited to process concerns.
- **Composition root:** `warden/internal/app` constructs production dependencies.
  Transport registration accepts already-built services and must not create
  alternate authorizers, audit loggers, resolvers, or lifecycle components.
- **No public Go API:** every package lives under `warden/internal/`. The
  authorization contract, scopes, and capability matching helpers live in
  `warden/internal/authz`, alongside the concrete PostgreSQL executor.
- **Interface policy:** authorization is a concrete `*authz.Authorizer` struct
  (`authz.New(pool)`), not an interface — consistent with every other domain. A
  domain service is a plain `*Service` struct, and where one domain depends on
  another it declares a **narrow consumer-side interface** naming only the methods
  it uses (e.g. catalog's `sessionTerminator` / `requestReadAuthorizer`, or the
  local scope-capability seam the connect helpers consume), rather than importing a
  producer-defined interface. This keeps dependencies explicit and testable without
  a package of shared mock interfaces.
- **Rust workspace:** members under the root `Cargo.toml`; shared deps in
  `[workspace.dependencies]`. `Cargo.lock` is committed (binary workspace).

## Protobuf codegen

- Contracts live in `proto/` (buf module). Service/message naming follows buf's
  `STANDARD` lint (service names end in `Service`).
- **Go stubs are committed** under `warden/gen/` so consumers build without a
  codegen step; regenerate with `make gen` and commit the result (it must be
  deterministic — CI checks for drift).
- **Rust** consumes protos via `tonic-build` in each crate's `build.rs` (output in
  `target/`, not committed).

## Data layer

- **Postgres** accessed via **sqlc + pgx/v5**: write SQL in `warden/internal/postgres/queries`, generate typed Go into `warden/internal/postgres/sqlc` with `make sqlc` (config: `sqlc.yaml`). Generated code is committed. `make sqlc` runs sqlc in database-backed analysis mode: it spins an ephemeral Postgres, applies the schema with `goose`, and points sqlc at it (so queries over the `authz_*` SQL functions resolve their return columns); the devshell provides `initdb`/`pg_ctl`/`goose`, so no external database is needed.
- **Migrations** are goose SQL files in `warden/internal/postgres/migrate/migrations`, embedded in the binary and applied on startup (`migrate.Up`). While Jumpgate is pre-production, `0001_schema.sql` is the canonical fresh-install schema and may be rewritten instead of carrying upgrade history. After a schema rewrite, reset local data with `make ui-dev-reset`; existing databases are not upgrade-compatible.
- **Authorization** goes through the `internal/authz` `Authorizer` seam; the current backend resolves access with a set of inlinable PostgreSQL **SQL functions** (`authz_held`, `authz_held_standing`, `authz_global_held`, `authz_user_groups`, `authz_role_goals`, `authz_effective_request_policy`, over the `active_access_grants` view — defined in `0001_schema.sql`) reached through static, typed sqlc queries in `warden/internal/postgres/queries/authz.sql`. Those functions are the **single source** of the recursive-closure logic: a grep-guard (`internal/authz/no_raw_closure_sql_test.go`, `TestNoRawClosureSQLInGo`) fails the build if a `WITH RECURSIVE` closure or a hand-rolled `user_groups`/`held_standing`/`global_held` CTE is re-introduced in Go (outside generated sqlc).
- **Integration tests** boot an ephemeral Postgres via `internal/testsupport` (uses the devshell's `initdb`/`pg_ctl`, no Docker). They `t.Skip` when that tooling isn't on PATH, so run them inside `nix develop`.
- Config is env-based (`internal/config`); see `DATABASE_URL`, `LISTEN_ADDR`, `SHUTDOWN_TIMEOUT`.

## API (ConnectRPC)

- The API is split into focused services: `AuthService` (login/whoami), `IdentityService` (users/groups/memberships), `CatalogService` (folders/assets — create / rename+move (`UpdateFolder`/`UpdateAsset`) / delete (`DeleteFolder`/`DeleteAsset`), path-scoped `ListFolders`/`ListAssets` (visibility-filtered, keyset-paginated), `GetAssetAccess`/`GetFolderAccess` (capabilities on selection), and `Resolve*`; asset SSH config is written type-safely — the asset kind and each login's auth kind are `oneof` arms, and onboarding seals secrets + creates the asset in one atomic call — and moves that break folder-scoped-role containment or form a cycle are refused, with an allowed move firing `authz_changed`), `AccessService` (all authorization config — roles, role-grants, standing role-bindings, request-policies + `ExplainRole`), `AccessRequestService` (the JIT runtime — request/approve/deny/cancel/revoke + grants + reaper), `VaultService` (CAs, mesh certs, session key, asset secrets), `SessionService` (`CreateSession` admission tokens), `RecordingService`, `GatewayService`, and a mesh-only `Dataplane` contract for workers. A per-RPC-service breakdown lives in [architecture.md](architecture.md#control-plane--go).
- Services are defined in `proto/` (buf) and generated to `warden/gen/...` — connect handlers live in the `*connect/` sub-packages. Run `make gen`.
- Served by `internal/rpc` (mounted on the same HTTP server as `/healthz`; one connect handler speaks Connect + gRPC + gRPC-Web, no Envoy).
- Auth is a bearer-token Connect interceptor (`internal/auth`): `Authorization: Bearer <token>` → current user in context; per-RPC capability guards (the shared `apiguard.Guard.RequireCap`) enforce access — management authz is capability-only (no `is_admin` flag; the bootstrap admin holds `**` via a global role binding). Tokens are opaque, stored hashed (argon2id passwords), revocable server-side.
- Validation via protovalidate (CEL constraints in the `.proto`). Errors use Connect codes; non-visible resources return `CodeNotFound` (never `PermissionDenied`) to avoid leaking existence.
- **Timestamps:** typed control-plane RPCs use `google.protobuf.Timestamp`; the worker/data-plane binary path uses `int64 *_unix_ms` for compactness; RFC3339 strings appear only in human-facing DTO fields (e.g. `created_at`/`expires_at` on access-request DTOs) — legacy; prefer `google.protobuf.Timestamp` for new typed fields.
- **Pagination:** `List*` RPCs keyset-paginate via `page_token`/`next_page_token`, with `page_size` bounded `[0, 100]`. The lone exception is `CatalogService.ListFolderContents`, which is a bounded *preview* (first ~50 of each kind, `*_has_more` signals truncation, no page tokens); callers needing the full list of a kind must use the per-kind `List*` RPC.
- Bootstrapping: there is no self-signup — on first startup an initial admin is seeded automatically when `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` are set in the environment. Without those vars no admin is pre-created; subsequent admin creation requires a direct DB seed.

## Adding a domain / RPC (vertical slice)

warden is organized as **vertical-slice domain modules** under `internal/` (`auth`,
`identity`, `catalog`, `access`, `accessrequest`, `vault`, `recording`, `session`,
and the mesh-facing `gateway`/`dataplane`). Each module is two files:

- **`service.go` — proto-free domain logic.** Owns the pool (for multi-step
  transactions), the sqlc `*Queries`, and any collaborators, and carries the
  transactional/business invariants. It takes the caller's `uuid.UUID` explicitly
  (never reads the request context) and returns plain domain structs, not proto
  messages. Cross-domain dependencies are **narrow consumer-side interfaces** defined
  here (see the interface policy above).
- **`handler.go` — ConnectRPC transport.** A thin `*Handler` wrapping the service and
  an `apiguard.Guard`. The generated-interface method does exactly: extract the caller
  (`caller(ctx)` → `auth.UserFromContext`), apply the coarse capability gate
  (`h.guard.RequireCap(ctx, caller, "<cap>", scope)`), call **one** service method,
  map the domain result to/from proto, and translate errors. Methods whose capability
  and visibility checks are entangled with DB work instead gate *in* the service
  (which mirrors `RequireCap`), taking the caller explicitly.

The shared **transport leaves** carry the cross-cutting concerns so a handler stays
thin, and none of them import a domain module (which is what lets `internal/rpc`
mount every handler without an import cycle):

- **`apiguard`** — `Guard.RequireCap` (deny unless the caller holds a capability at a
  scope), `Guard.RequireGrantable` (the no-escalation subset rule), and the scope
  derivations (`ScopeOfFolderID`, `ScopeOfObject`, `ScopeOfRole`, …).
- **`apierr`** — `MapWrite` (Postgres constraint error → `InvalidArgument`/
  `AlreadyExists` rather than `Internal`) and the `pgx.ErrNoRows` → `NotFound`
  existence-hiding mappers.
- **`apipage`** — the keyset-cursor codec (`ClampPageSize`, `Encode*Token`,
  `DecodePageToken`) shared by every `List*` RPC.

To add an RPC: define it in `proto/` and `make gen`; add the SQL to
`warden/internal/postgres/queries` and `make sqlc`; put the logic in the domain
`service.go`; add the transport method to `handler.go` (gate → call → map); and, if
the module is new, register its constructed handler in `internal/rpc/services.go`
(`RegisterUserServices` or `RegisterMeshServices`) and wire its construction in
`internal/app`. `internal/rpc` is wiring only — it never constructs authorizers,
audit loggers, or other dependencies.

## Web UI

The `web/` directory holds the browser SPA: **Vite + React + TypeScript**. It talks
to warden over ConnectRPC using **[@connectrpc/connect-query](https://connectrpc.com/docs/web/query/)**
layered on **TanStack Query**, over a **same-origin** Connect transport configured
with `credentials: "include"` so the browser attaches the session cookie to every
request. The SPA is served from the same origin as the API (Vite proxies in dev,
warden's embedded handler in prod), so there is no CORS layer and no cross-origin
token handling.

### Auth in the browser

The app is cookie-session based and never handles a raw token:

- On sign-in the SPA calls `AuthService.Login` with `cookie_only: true`. Warden
  sets an **httpOnly** `jumpgate_session` cookie via `Set-Cookie` and returns an
  empty `token` field — JavaScript cannot read the credential.
- On load (and after login) the app calls `AuthService.WhoAmI`; the returned
  `capabilities` drive nav gating and which actions the UI offers.
- Sign-out calls `AuthService.Logout`, which revokes the token server-side and
  clears the cookie (`MaxAge=-1`).

CSRF protection, cookie flags (`HttpOnly`, `Secure`, `SameSite`), and the
`Sec-Fetch-Site: same-origin` gate are covered in
[security.md](security.md#authn--token-model).

### Codegen

`make gen` (buf) emits **both** Go stubs into `warden/gen/` and **TypeScript**
stubs into `web/src/gen/`. Both are committed; regenerate with `make gen` and
commit the result.

### Dev environment

`make ui-dev` starts a full local stack via **process-compose**: a persistent
Postgres, a silo (S3-compatible) object store, a hot-reloading warden (`air`), and
the Vite dev server with HMR. Vite proxies API/`/healthz` requests to warden on
`:8080`, so the browser sees a single same-origin app and cookie auth works over
plain HTTP (warden runs with `JUMPGATE_COOKIE_INSECURE=true` here). All state lives
under `.devdata/` (gitignored) and persists across restarts; `make ui-dev-reset`
wipes it for a clean re-provision on the next `ui-dev`.

Run it inside the Nix devshell (it uses `initdb`/`pg_ctl`, `silo`, `air`, and
`pnpm` from the shell). The dev admin account is seeded by the bootstrap step:
`admin@dev.local` / `devpassword123`.

### Production serving

For production, the SPA is built (`web/dist`) and **embedded into the warden
binary** behind the `embedui` build tag: the Docker image builds `web/dist` and
compiles warden with `go build -tags embedui ./cmd/warden`, and warden serves the SPA
same-origin alongside the API. The default `go build` (no tag) omits the SPA
entirely, so Go builds and tests need no frontend toolchain — in development Vite
serves the app instead.

### Console views

The console supports **light and dark themes** (following the OS preference by
default, with a header toggle), and a **⌘K command palette** (also reachable from
the header search affordance) that searches the catalog via `SearchCatalog` —
results are visibility-filtered and grouped by kind (folders/assets/roles/groups);
selecting one opens that node in the Catalog.

The SPA is a single-page console over four views, gated by the caller's
capabilities (from `WhoAmI`):

- **Catalog** (`/`) — a lazy governance tree of folders with their assets, roles,
  and groups. Each node loads its children on expand (`ListFolderContents`), and
  selecting an asset opens a detail pane showing the caller's capabilities and
  active roles on it, any requestable roles, and — when SSH connect capabilities
  are present — a ready-to-run `jumpgate connect` command. Requestable roles open
  a slide-over that files a JIT request (`RequestAccess`) with a role, duration,
  and reason.
- **My Access** (`/access`) — the caller's own JIT lifecycle: a **Requests** tab
  (pending/granted/denied with status badges) and a **Grants** tab (active grants
  with a live expiry countdown, self-revoke, and the copy-able connect command the
  server derives for each grant).
- **Approvals** (`/approvals`) — the approver inbox of pending requests the caller
  may decide, with inline approve and a confirm-dialog deny. The nav badge shows
  the pending count. Each row resolves the requester, asset, and role — and, behind
  a compact toggle, the request's **decision context**: the SSH target host and the
  capabilities the requested role grants, so an approver can judge in place.

The Approvals inbox and My Access resolve those names/paths through dedicated
**display reads** — a universal `GetUserDisplay` (any authenticated caller, for
rendering user names/avatars) plus request-scoped `GetAssetDisplay` / `GetRoleDisplay`
that a caller may read when they hold the entity's read capability *or* are party to
a pending access request that references it. The display payloads never carry secret
references (an asset's stored-secret ids are omitted); the full `GetAsset` still
requires `catalog:asset:read`.
- **Recordings** (`/recordings`, only when the caller holds `recording:read`) —
  the audit list of session recordings with an in-browser **asciinema** player
  that streams each cast same-origin from `/api/recordings/<id>/cast` (the session
  cookie rides along).
- **Terminal** (`/terminal/:assetId?login=…`, a chromeless full-screen xterm.js
  view opened via "Open terminal" on an asset/grant) — an in-browser SSH session,
  recorded and governed exactly like `jumpgate connect`. The browser fetches a
  short-lived `CreateWebSession` ticket, opens a WebSocket to the gateway, which
  verifies it and relays a byte-accurate opcode protocol over the mesh to the
  ssh-proxy worker's WebSocket-terminal ingress (which runs the target SSH +
  records). In production set `GATEWAY_CONSOLE_ORIGIN` to the console origin so the
  gateway restricts terminal WebSockets to it.
- **Access control** (`/access-control`, shown when the caller holds an `access:*`
  read cap) — manage the governance rules across **Roles** (create with a validated
  capability set + optional folder scope; manage role-grant edges; **cascade delete**
  that also removes the role's bindings, policies, and grants and ends the live
  sessions it grants), **Bindings** (bind a role to a user/group at a folder/asset/
  global scope), and **Policies** (request policies: requestable role, scope,
  min-approvals, requester/approver roles + subjects, max duration). Roles have no
  update RPC, so capabilities are fixed at creation.
- **Directory** (`/directory`, shown when the caller holds `identity:user:read` or
  `identity:group:read`) — manage users and groups. **Users:** list with an
  active/deactivated status, create, deactivate/reactivate, delete (destructive
  actions confirm, and you can't act on your own account). **Groups:** list, create
  (with an optional folder home), delete, and a detail drawer that manages
  membership — both user members and nested sub-groups (add via searchable pickers,
  remove inline). Every affordance is gated on the caller's global management
  capabilities; the server remains the enforcer.

## Testing

The test **tiers** (in-package unit/integration, local data-plane e2e, cluster e2e,
UI e2e) — what each proves and which run in CI — are documented in
[testing.md](testing.md). A quick command reference:

- **Web:** `make web` installs, typechecks (`tsc --noEmit`), and builds the SPA;
  this runs as part of `make ci`. `make ui-e2e` runs the **Playwright** suite
  (Nix-provided chromium) against the kind environment where warden serves the
  embedded SPA — it is opt-in and kept out of `ci` (like `e2e-cluster`). It first
  seeds the fixtures via the CLI (`TestUISeed` in `test/e2e`: a JIT-requestable
  asset gated by a cross-approval policy, plus a standing-access asset that alice
  connects to so the audit view has a completed recording), then drives the
  multi-actor browser story in `web/e2e/access-loop.spec.ts` — alice requests
  access, bob approves, alice sees her grant's connect command, and an admin
  auditor plays the recording back — each actor in an isolated browser context.
  The seed assumes a fresh `kind-up`; pass `KEEP=1` to leave the cluster running
  after the run.
- **Go:** standard `go test`; tests exercise real behavior (e.g. the warden
  health test drives an `httptest` server and decodes real JSON). Integration tests
  boot an ephemeral Postgres via `internal/testsupport` (initdb/pg_ctl, no Docker).
- **Rust:** `cargo nextest`; axum handlers tested via `tower::ServiceExt::oneshot`.
- Prefer tests that verify behavior over mocks.

## Adding a new protocol worker

Because the gateway is protocol-agnostic, a new worker only needs to speak two
contracts: the gateway↔worker forwarding frame and the worker↔control-plane mesh
gRPC service. Implement those, register the pool, and the worker can be in any
language (Rust or Go). See
[architecture.md](architecture.md#protocol-workers--rust).

## Status

SSH access works end to end — the control plane, the Rust gateway, the ssh-proxy
worker, and the `jumpgate` CLI, with JIT request/approval, envelope-encrypted
secrets, capability-driven credentials, continuous revocation, and session
recording all live and exercised by the `test/e2e` suite against a kind cluster.
A browser SPA (`web/`) is served same-origin against the same ConnectRPC API.
Postgres/Kubernetes/RDP workers, inline step-up, and enterprise SSO are not yet
built. See [roadmap.md](roadmap.md).
