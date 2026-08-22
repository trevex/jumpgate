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

- **Postgres** accessed via **sqlc + pgx/v5**: write SQL in `warden/internal/db/queries`, generate typed Go into `warden/internal/db/gen` with `sqlc generate` (config: `sqlc.yaml`). Generated code is committed.
- **Migrations** are goose SQL files in `warden/internal/db/migrate/migrations`, embedded in the binary and applied on startup (`migrate.Up`).
- **Authorization** goes through the `internal/authz` `Authorizer` seam; the current backend resolves access with recursive SQL CTEs over Postgres.
- **Integration tests** boot an ephemeral Postgres via `internal/testsupport` (uses the devshell's `initdb`/`pg_ctl`, no Docker). They `t.Skip` when that tooling isn't on PATH, so run them inside `nix develop`.
- Config is env-based (`internal/config`); see `DATABASE_URL`, `LISTEN_ADDR`, `SHUTDOWN_TIMEOUT`.

## API (ConnectRPC)

- The API is split into focused services: `AuthService` (login/whoami), `IdentityService` (users/groups/memberships), `CatalogService` (folders/assets — path-scoped `ListFolders`/`ListAssets` (visibility-filtered, keyset-paginated), `GetAssetAccess`/`GetFolderAccess` (capabilities on selection), and `Resolve*`), `AccessService` (all authorization config — roles, role-grants, standing role-bindings, request-policies + `ExplainRole`), `AccessRequestService` (the JIT runtime — request/approve/deny/cancel/revoke + grants + reaper), `VaultService` (CAs, mesh certs, session key, asset secrets), `SessionService` (`CreateSession` admission tokens), `RecordingService`, `GatewayService`, and a mesh-only `Dataplane` contract for workers. A per-RPC-service breakdown lives in [architecture.md](architecture.md#control-plane--go).
- Services are defined in `proto/` (buf) and generated to `warden/gen/...` — connect handlers live in the `*connect/` sub-packages. Run `make gen`.
- Served by `internal/rpc` (mounted on the same HTTP server as `/healthz`; one connect handler speaks Connect + gRPC + gRPC-Web, no Envoy).
- Auth is a bearer-token Connect interceptor (`internal/auth`): `Authorization: Bearer <token>` → current user in context; per-RPC capability guards (`capGuard.requireCap`) enforce access — management authz is capability-only (no `is_admin` flag; the bootstrap admin holds `**` via a global role binding). Tokens are opaque, stored hashed (argon2id passwords), revocable server-side.
- Validation via protovalidate (CEL constraints in the `.proto`). Errors use Connect codes; non-visible resources return `CodeNotFound` (never `PermissionDenied`) to avoid leaking existence.
- Bootstrapping: there is no self-signup — on first startup an initial admin is seeded automatically when `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` are set in the environment. Without those vars no admin is pre-created; subsequent admin creation requires a direct DB seed.

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
compiles warden with `go build -tags embedui`, and warden serves the SPA
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

## Testing

- **Web:** `make web` installs, typechecks (`tsc --noEmit`), and builds the SPA;
  this runs as part of `make ci`. `make ui-e2e` runs the **Playwright** suite
  (Nix-provided chromium) against the kind environment where warden serves the
  embedded SPA — it is opt-in and kept out of `ci` (like `kind-e2e`). It first
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
