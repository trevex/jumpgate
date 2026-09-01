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

- Go to the `warden/go.mod` minor's latest patch (via `go-overlay`).
- Rust to the channel in `rust-toolchain.toml` (stable), through `rustup`.
- Codegen and infra tooling at the versions locked in `flake.lock`.

Pre-commit hooks (rustfmt, clippy `-D warnings`, gofmt, golangci-lint) are wired by
`git-hooks.nix` and installed on devshell entry. Because the hooks call `cargo` and
`go`, commit from inside the devshell (`nix develop -c git commit …`, or with direnv
active) or the hooks fail to find the toolchain.

## Common tasks (Makefile)

Run inside the devshell:

| Command | Does |
|---------|------|
| `make gen` | Generate protobuf stubs (Go and Rust) and sqlc DB code |
| `make build` | Build the Go and Rust binaries |
| `make test` | Run Go and Rust tests |
| `make lint` | gofmt, golangci-lint, rustfmt, clippy |
| `make fmt` | Auto-format Go and Rust |
| `make web` | Install, typecheck (`tsc --noEmit`), and build the SPA |
| `make ci` | Full pipeline: gen → build → test → lint → web (what CI runs) |
| `make ui-dev` | Start the UI dev stack (process-compose: Postgres, silo, warden, Vite) |
| `make ui-dev-reset` | Wipe local dev data (`.devdata/`); full re-provision on next `ui-dev` |
| `make docs-serve` | Serve the docs site with live reload at `http://127.0.0.1:8000/` |
| `make kind-up` | Create the kind cluster, install cert-manager and the chart, deploy the sshd workload |
| `make kind-demo` | `kind-up` plus export the mesh CA and print the CLI setup |
| `make e2e-cluster` | Cluster-tier black-box e2e (kind plus CLI); teardown after (`KEEP=1` keeps it) |
| `make ui-e2e` | Bring up kind (warden serves the embedded SPA) and run Playwright (opt-in) |

CI (`.github/workflows/ci.yml`) runs `nix develop -c make ci`, so local and CI behavior
are identical.

## Repository layout

```
warden/             Go   — API, identity, authz, vault, JIT/approvals, enrollment, audit, data-plane control
gateway/            Rust — session router / load balancer (only exposed component)
workers/            per-protocol proxies: ssh-proxy (Rust), pg-proxy (Go), k8s-broker (Go), k8s-agent (Go)
cli/                Go   — `jumpgate` CLI
web/                     — web SPA (Vite + React + TS), embedded in warden under -tags embedui
proto/              Shared gRPC/protobuf contracts (buf)
deploy/helm/        Helm chart (kind + cert-manager)
test/               End-to-end suite (test/e2e) and the kind test environment (test/env)
docs/               This documentation
flake.nix .envrc    Nix devshell + direnv
rust-toolchain.toml Pinned Rust toolchain
go.work             Go workspace (warden, cli, test/e2e, and the Go workers)
Cargo.toml Cargo.lock Rust workspace (gateway, mesh, ssh-proxy)
Makefile            Task entrypoints
```

The SSH worker is Rust (russh); the Postgres and Kubernetes workers are Go, so a
protocol lives in whichever language best fits it behind the shared gateway. The
k8s-agent deploys into target clusters, not the jumpgate chart.

## Module & package conventions

- Go module path: `github.com/trevex/jumpgate/warden` (matches the repo URL).
  Additional Go modules (`cli`, the Go workers, `test/e2e`) are added to `go.work`.
- Go commands: executable entrypoints live under `warden/cmd/`; the primary daemon is
  `warden/cmd/warden`. Process lifecycle and dependency wiring live in
  `warden/internal/app`, keeping command packages limited to process concerns.
- Composition root: `warden/internal/app` constructs production dependencies. Transport
  registration accepts already-built services and must not create alternate
  authorizers, audit loggers, resolvers, or lifecycle components.
- No public Go API: every package lives under `warden/internal/`. The authorization
  contract, scopes, and capability matching helpers live in `warden/internal/authz`,
  alongside the concrete PostgreSQL executor.
- Interface policy: authorization is a concrete `*authz.Authorizer` struct
  (`authz.New(pool)`), not an interface — consistent with every other domain. A domain
  service is a plain `*Service` struct, and where one domain depends on another it
  declares a narrow consumer-side interface naming only the methods it uses, rather than
  importing a producer-defined interface. This keeps dependencies explicit and testable
  without a package of shared mock interfaces.
- Rust workspace: members under the root `Cargo.toml` (`gateway`, `mesh`,
  `workers/ssh-proxy`); shared deps in `[workspace.dependencies]`. `Cargo.lock` is
  committed.

## Protobuf codegen

- Contracts live in `proto/` (buf module). Service and message naming follows buf's
  `STANDARD` lint (service names end in `Service`).
- Go stubs are committed under `warden/gen/` so consumers build without a codegen step;
  regenerate with `make gen` and commit the result (it must be deterministic — CI checks
  for drift).
- The Rust gateway and ssh-proxy consume protos via `tonic-build` in each crate's
  `build.rs` (output in `target/`, not committed). The Go workers use the committed Go
  stubs.

## Data layer

- Postgres is accessed via sqlc plus pgx/v5: write SQL in
  `warden/internal/postgres/queries`, generate typed Go into
  `warden/internal/postgres/sqlc` with `make sqlc` (config: `sqlc.yaml`). Generated code
  is committed. `make sqlc` runs sqlc in database-backed analysis mode: it spins an
  ephemeral Postgres, applies the schema with goose, and points sqlc at it (so queries
  over the `authz_*` SQL functions resolve their return columns); the devshell provides
  `initdb`, `pg_ctl`, and `goose`, so no external database is needed.
- Migrations are goose SQL files in `warden/internal/postgres/migrate/migrations`,
  embedded in the binary and applied on startup (`migrate.Up`). The schema is currently
  `0001_schema.sql` (core) plus additive migrations for the Postgres asset tables,
  Kubernetes agent enrollment, and the management-visibility functions. While jumpgate is
  pre-production, migrations may be squashed rather than carrying long upgrade history;
  after a squash, reset local data with `make ui-dev-reset`, since existing databases are
  not upgrade-compatible.
- Authorization goes through the `internal/authz` `Authorizer` seam; the current backend
  resolves access with a set of inlinable PostgreSQL SQL functions (`authz_held`,
  `authz_held_standing`, `authz_global_held`, `authz_user_groups`, `authz_role_goals`,
  `authz_effective_request_policy`, over the `active_access_grants` view) reached through
  static, typed sqlc queries in `warden/internal/postgres/queries/authz.sql`. Those
  functions are the single source of the recursive-closure logic: a grep-guard
  (`internal/authz/no_raw_closure_sql_test.go`, `TestNoRawClosureSQLInGo`) fails the build
  if a `WITH RECURSIVE` closure or a hand-rolled CTE is re-introduced in Go.
- Integration tests boot an ephemeral Postgres via `internal/testsupport` (initdb/pg_ctl,
  no Docker). They `t.Skip` when that tooling is not on PATH, so run them inside
  `nix develop`.
- Config is env-based (`internal/config`); see `DATABASE_URL`, `LISTEN_ADDR`,
  `SHUTDOWN_TIMEOUT`.

## API (ConnectRPC)

- The API is split into focused services: `AuthService` (login/whoami),
  `IdentityService` (users/groups/memberships), `CatalogService` (folders and assets —
  create, rename/move, delete; path-scoped `ListFolders`/`ListAssets`;
  `GetAssetAccess`/`GetFolderAccess`; `SearchCatalog`; `Resolve*`; typed SSH, Postgres,
  and Kubernetes config written as `oneof` arms so onboarding is atomic), `AccessService`
  (roles, role-grants, standing role-bindings, request-policies, `ExplainRole`),
  `AccessRequestService` (the JIT runtime), `VaultService` (CAs, mesh certs, session key,
  asset secrets), `EnrollmentService` (Kubernetes agent enrollment tokens and
  `SignAgentCert`), `SessionService` (`CreateSession`, `CreatePostgresSession`,
  `CreateKubernetesSession`, `CreateWebSession`), `RecordingService`, `GatewayService`,
  and a mesh-only `Dataplane` contract for workers. A per-RPC-service breakdown lives in
  [architecture.md](architecture.md#control-plane--go).
- Services are defined in `proto/` (buf) and generated to `warden/gen/…`; connect handlers
  live in the `*connect/` sub-packages. Run `make gen`.
- Served by `internal/rpc` (mounted on the same HTTP server as `/healthz`; one connect
  handler speaks Connect, gRPC, and gRPC-Web, no Envoy).
- Auth is a Connect interceptor (`internal/auth`): a bearer token or a same-origin
  session cookie resolves the current user into context; per-RPC capability guards (the
  shared `apiguard.Guard.RequireCap`) enforce access — management authz is capability-only
  (no `is_admin` flag). Tokens are opaque, stored hashed (argon2id passwords), revocable
  server-side.
- Validation via protovalidate (CEL constraints in the `.proto`). Errors use Connect
  codes; non-visible resources return `CodeNotFound` (never `PermissionDenied`) to avoid
  leaking existence.
- Timestamps: typed control-plane RPCs use `google.protobuf.Timestamp`; the worker/
  data-plane binary path uses `int64 *_unix_ms` for compactness.
- Pagination: `List*` RPCs keyset-paginate via `page_token`/`next_page_token`, with
  `page_size` bounded `[0, 100]`. The exception is `CatalogService.ListFolderContents`, a
  bounded preview (first ~50 of each kind, `*_has_more` signals truncation, no page
  tokens); callers needing the full list of a kind use the per-kind `List*` RPC.
- Bootstrapping: there is no self-signup. On first startup an initial admin is seeded when
  `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` are set. Without those vars no
  admin is pre-created; subsequent admin creation requires a direct DB seed.

## Adding a domain / RPC (vertical slice)

warden is organized as vertical-slice domain modules under `internal/` (`auth`,
`identity`, `catalog`, `access`, `accessrequest`, `vault`, `enrollment`, `recording`,
`session`, and the mesh-facing `gateway` and `dataplane`). Each module is two files:

- `service.go` — proto-free domain logic. Owns the pool (for multi-step transactions),
  the sqlc `*Queries`, and any collaborators, and carries the transactional and business
  invariants. It takes the caller's `uuid.UUID` explicitly (never reads the request
  context) and returns plain domain structs, not proto messages. Cross-domain
  dependencies are narrow consumer-side interfaces defined here.
- `handler.go` — ConnectRPC transport. A thin `*Handler` wrapping the service and an
  `apiguard.Guard`. The generated-interface method extracts the caller
  (`caller(ctx)` → `auth.UserFromContext`), applies the coarse capability gate
  (`h.guard.RequireCap(ctx, caller, "<cap>", scope)`), calls one service method, maps the
  domain result to and from proto, and translates errors. Methods whose capability and
  visibility checks are entangled with DB work instead gate in the service (which mirrors
  `RequireCap`), taking the caller explicitly.

The shared transport leaves carry the cross-cutting concerns so a handler stays thin, and
none of them import a domain module (which is what lets `internal/rpc` mount every handler
without an import cycle):

- `apiguard` — `Guard.RequireCap`, `Guard.RequireGrantable` (the no-escalation subset
  rule), and the scope derivations (`ScopeOfFolderID`, `ScopeOfObject`, `ScopeOfRole`).
- `apierr` — `MapWrite` (Postgres constraint error → `InvalidArgument` / `AlreadyExists`
  rather than `Internal`) and the `pgx.ErrNoRows` → `NotFound` existence-hiding mappers.
- `apipage` — the keyset-cursor codec (`ClampPageSize`, `Encode*Token`, `DecodePageToken`)
  shared by every `List*` RPC.

To add an RPC: define it in `proto/` and `make gen`; add the SQL to
`warden/internal/postgres/queries` and `make sqlc`; put the logic in the domain
`service.go`; add the transport method to `handler.go` (gate → call → map); and, if the
module is new, register its constructed handler in `internal/rpc/services.go` and wire its
construction in `internal/app`. `internal/rpc` is wiring only.

## Adding a new protocol worker

Because the gateway is protocol-agnostic, a new worker only needs to speak two contracts:
the gateway↔worker forwarding frame and the worker↔control-plane mesh gRPC service.
Implement those, register the pool, and the worker can be in any language — as the Go
pg-proxy and k8s workers show alongside the Rust ssh-proxy. See
[architecture.md](architecture.md#data-plane).

## Web UI

The `web/` directory holds the browser SPA: Vite, React, and TypeScript. It talks to
warden over ConnectRPC using
[@connectrpc/connect-query](https://connectrpc.com/docs/web/query/) layered on TanStack
Query, over a same-origin Connect transport configured with `credentials: "include"` so
the browser attaches the session cookie to every request. The SPA is served from the same
origin as the API (Vite proxies in dev, warden's embedded handler in prod), so there is no
CORS layer and no cross-origin token handling.

### Auth in the browser

The app is cookie-session based and never handles a raw token:

- On sign-in the SPA calls `AuthService.Login` with `cookie_only: true`. warden sets an
  `httpOnly` `jumpgate_session` cookie via `Set-Cookie` and returns an empty `token`
  field, so JavaScript cannot read the credential.
- On load (and after login) the app calls `AuthService.WhoAmI`; the returned
  `capabilities` drive nav gating and which actions the UI offers.
- Sign-out calls `AuthService.Logout`, which revokes the token server-side and clears the
  cookie.

CSRF protection, cookie flags, and the `Sec-Fetch-Site: same-origin` gate are covered in
[security.md](security.md#authn--token-model).

### Codegen

`make gen` (buf) emits both Go stubs into `warden/gen/` and TypeScript stubs into
`web/src/gen/`. Both are committed; regenerate with `make gen` and commit the result.

### Dev environment

`make ui-dev` starts a full local stack via process-compose: a persistent Postgres, a
silo (S3-compatible) object store, a hot-reloading warden (`air`), and the Vite dev server
with HMR. Vite proxies API and `/healthz` requests to warden on `:8080`, so the browser
sees a single same-origin app and cookie auth works over plain HTTP (warden runs with
`JUMPGATE_COOKIE_INSECURE=true` here). All state lives under `.devdata/` (gitignored) and
persists across restarts; `make ui-dev-reset` wipes it. Run it inside the Nix devshell.
The dev admin account is seeded by the bootstrap step: `admin@dev.local` / `devpassword123`.

### Production serving

For production, the SPA is built (`web/dist`) and embedded into the warden binary behind
the `embedui` build tag: the Docker image builds `web/dist` and compiles warden with
`go build -tags embedui ./cmd/warden`, and warden serves the SPA same-origin alongside the
API. The default `go build` (no tag) omits the SPA, so Go builds and tests need no
frontend toolchain — in development Vite serves the app instead.

### Console views

The console supports light and dark themes (following the OS preference by default, with a
header toggle) and a ⌘K command palette that searches the catalog via `SearchCatalog`
(results are visibility-filtered and grouped by kind). The SPA is gated by the caller's
capabilities (from `WhoAmI`) and offers:

- Overview (`/`) — a persona-aware dashboard: the caller's active grants and pending
  requests, approvals awaiting them, and recent recordings, each linking through.
- Catalog (`/catalog`) — a two-pane governance browser. The left pane is a lazy folder
  tree; the right pane is a kind-adaptive detail panel for the selected asset, folder,
  role, or group. Selecting an asset shows the caller's capabilities and active roles, any
  requestable roles (which open a slide-over that files a JIT request), and a ready-to-run
  connect command. This is also where assets are authored: a create wizard toggles between
  SSH, Postgres, and Kubernetes, and SSH and Postgres configs are editable in place. A
  Kubernetes asset has no editable config; it exposes a re-mint enrollment-token action.
- My Access (`/access`) — the caller's own JIT lifecycle: a Requests tab and a Grants tab
  (active grants with a live expiry countdown, self-revoke, and a copy-able connect
  command).
- Approvals (`/approvals`) — the approver inbox of pending requests the caller may decide,
  with inline approve and a confirm-dialog deny. The nav badge shows the pending count.
  Each row resolves the requester, asset, and role, and can expand a decision-context
  panel. Names and paths come from dedicated display reads (`GetUserDisplay`,
  `GetAssetDisplay`, `GetRoleDisplay`) that a caller may read for entities they can see or
  are party to a pending request about; the display payloads never carry secret references.
- Directory (`/directory`) — manage users (create, deactivate/reactivate, delete) and
  groups (create with an optional folder home, delete, and a membership drawer for user
  members and nested sub-groups). Every affordance is gated on the caller's management
  capabilities; the server remains the enforcer.
- Access control (`/access-control`) — author the governance rules across Roles (with a
  validated capability set and optional folder scope; grant edges; cascade delete),
  Bindings, and Policies. Roles have no update RPC, so capabilities are fixed at creation.
- Recordings (`/recordings`, when the caller holds `recording:read`) — the audit list with
  a format-aware player: an asciinema player for SSH, a statement timeline for
  `pgwire-timeline-v1`, and an API-request table for `k8s-audit-v1`.
- Terminal (`/terminal/:assetId?login=…`, a chromeless xterm.js view) — an in-browser SSH
  session, recorded and governed like `jumpgate connect`. The browser fetches a
  short-lived `CreateWebSession` ticket, opens a WebSocket to the gateway, and the gateway
  relays a byte-accurate opcode protocol over the mesh to the ssh-proxy's WebSocket
  ingress. In production set `GATEWAY_CONSOLE_ORIGIN` so the gateway restricts terminal
  WebSockets to the console origin. There is no in-browser SQL or Kubernetes console;
  Postgres is reached through the loopback CLI proxy.

## Testing

The test tiers (in-package unit/integration, cluster e2e, UI e2e) — what each proves and
which run in CI — are documented in [testing.md](testing.md). A quick command reference:

- Web: `make web` installs, typechecks, and builds the SPA; this runs as part of
  `make ci`. `make ui-e2e` runs the Playwright suite (Nix-provided chromium) against the
  kind environment where warden serves the embedded SPA. It is opt-in and kept out of `ci`
  (like `e2e-cluster`).
- Go: standard `go test`; tests exercise real behavior. Integration tests boot an
  ephemeral Postgres via `internal/testsupport` (initdb/pg_ctl, no Docker).
- Rust: `cargo nextest`; axum handlers tested via `tower::ServiceExt::oneshot`.
- Prefer tests that verify behavior over mocks.

## Status

SSH, Postgres, and Kubernetes access all work end to end — the control plane, the Rust
gateway, the ssh-proxy (Rust), pg-proxy (Go), and k8s-broker/agent (Go), plus the
`jumpgate` CLI and the embedded web console — with JIT request and approval,
envelope-encrypted secrets, capability-driven credentials, continuous revocation, and
per-protocol recording, exercised by the `test/e2e` suite against a kind cluster. RDP,
inline Postgres step-up, and enterprise SSO are not yet built. See
[roadmap.md](roadmap.md).
