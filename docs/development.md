# Development

## Prerequisites

- [Nix](https://nixos.org/download) with flakes enabled.
- [direnv](https://direnv.net) (recommended) to auto-enter the devshell.

Everything else — Go, Rust, buf, protobuf, golangci-lint, Postgres, OpenFGA,
helm, kind, node/pnpm — is provided by the Nix devshell. Do not install
toolchains globally.

## Entering the devshell

```sh
direnv allow        # once; then the shell auto-enters on cd
# or, without direnv:
nix develop
```

The devshell pins:

- **Go** to the `control-plane/go.mod` minor's latest patch (via `go-overlay`).
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
| `make ci` | Full pipeline: gen → build → test → lint (what CI runs) |

CI (`.github/workflows/ci.yml`) simply runs `nix develop -c make ci`, so local and
CI behavior are identical.

## Repository layout

```
control-plane/      Go   — API, identity, authz, vault, JIT/approvals, audit, registry
gateway/            Rust — session router / load balancer (only exposed component)
workers/            Rust — per-protocol proxies (ssh-proxy, pg-proxy, …)   [planned]
cli/                Go   — `jumpgate` CLI                                    [planned]
web/                     — React + Vite SPA (embedded in control-plane)      [planned]
proto/              Shared gRPC/protobuf contracts (buf)
deploy/helm/        Helm chart + docker-compose                              [planned]
docs/               This documentation
flake.nix .envrc    Nix devshell + direnv
rust-toolchain.toml Pinned Rust toolchain
go.work             Go workspace
Cargo.toml Cargo.lock Rust workspace
Makefile            Task entrypoints
```

## Module & package conventions

- **Go module path:** `github.com/trevex/jumpgate/control-plane` (matches the repo
  URL). Additional Go modules (e.g. `cli`) are added to `go.work`.
- **Rust workspace:** members under the root `Cargo.toml`; shared deps in
  `[workspace.dependencies]`. `Cargo.lock` is committed (binary workspace).

## Protobuf codegen

- Contracts live in `proto/` (buf module). Service/message naming follows buf's
  `STANDARD` lint (service names end in `Service`).
- **Go stubs are committed** under `control-plane/gen/` so consumers build without a
  codegen step; regenerate with `make gen` and commit the result (it must be
  deterministic — CI checks for drift).
- **Rust** consumes protos via `tonic-build` in each crate's `build.rs` (output in
  `target/`, not committed).

## Data layer

- **Postgres** accessed via **sqlc + pgx/v5**: write SQL in `control-plane/internal/db/queries`, generate typed Go into `control-plane/internal/db/gen` with `sqlc generate` (config: `sqlc.yaml`). Generated code is committed.
- **Migrations** are goose SQL files in `control-plane/internal/db/migrate/migrations`, embedded in the binary and applied on startup (`migrate.Up`).
- **Authorization** goes through the `internal/authz` `Authorizer` seam; the current backend resolves access with recursive SQL CTEs over Postgres.
- **Integration tests** boot an ephemeral Postgres via `internal/testsupport` (uses the devshell's `initdb`/`pg_ctl`, no Docker). They `t.Skip` when that tooling isn't on PATH, so run them inside `nix develop`.
- Config is env-based (`internal/config`); see `DATABASE_URL`, `LISTEN_ADDR`, `SHUTDOWN_TIMEOUT`.

## Testing

- **Go:** standard `go test`; tests exercise real behavior (e.g. the control-plane
  health test drives an `httptest` server and decodes real JSON). Integration tests
  boot an ephemeral Postgres via `internal/testsupport` (initdb/pg_ctl, no Docker).
- **Rust:** `cargo nextest`; axum handlers tested via `tower::ServiceExt::oneshot`.
- Prefer tests that verify behavior over mocks.

## Adding a new protocol worker (future)

Because the gateway is protocol-agnostic, a new worker only needs to speak two
contracts: the gateway↔worker forwarding frame and the worker↔control-plane gRPC
service. Implement those, register the pool, and the worker can be in any language
(Rust or Go). See [architecture.md](architecture.md#protocol-workers--rust-).

## Current status

Milestone **M1 (foundation)** is complete: devshell, workspaces, protobuf codegen,
and `control-plane` + `gateway` `/healthz` binaries with green CI. See
[roadmap.md](roadmap.md) for what's next.
