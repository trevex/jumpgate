# Testing

jumpgate is tested in **tiers**, each aimed at a different layer so their coverage
stays complementary rather than redundant. Read this alongside the quick command
reference in [development.md](development.md#testing).

| Tier | Command | In CI? | Where | Proves |
|---|---|---|---|---|
| In-package unit & integration | `go test ./...` (via `make test`) | ✅ yes | `warden/`, `cli/` | domain logic, SQL/sqlc queries, the authz functions, handlers |
| Local data-plane e2e | `make e2e-local` | ❌ opt-in | `warden/e2e` | the real SSH data-plane binaries wire together (no cluster) |
| Cluster e2e | `make e2e-cluster` | ❌ opt-in | `test/e2e` | the shipped containers + CLI + Helm deliver the governance flow |
| UI e2e | `make ui-e2e` | ❌ opt-in | `web/e2e` | the browser console over the live stack |

`make ci` runs `make test` (+ `cargo nextest` and the web typecheck/build), so the
first tier is the everyday correctness gate; the three e2e tiers are opt-in and kept
out of `ci`.

## In-package unit & integration — the primary gate

`make test` runs `go test ./...` across the `warden` and `cli` modules (plus
`cargo nextest` for the Rust workspace and the web typecheck/build). This is what
`make ci` — and therefore CI — runs.

- **Unit tests** cover pure logic: capability matching/normalization, scope
  derivation, pagination codec, ltree helpers, error mapping.
- **Integration tests** boot a **real, ephemeral PostgreSQL** through
  `internal/testsupport.StartPostgres`, which uses the devshell's `initdb`/`pg_ctl`
  (no Docker) and tears the server down at test end. They `t.Skip` when that tooling
  is not on `PATH`, so run them inside `nix develop`; in CI the devshell provides it,
  so they execute. These tests exercise the sqlc queries and the **`authz_*` SQL
  functions** against the real migrated schema — including the drift/guard tests
  (`internal/authz/authz_functions_test.go`, and `no_raw_closure_sql_test.go`, which
  fails the build if closure SQL is hand-written in Go).
- **HTTP/handler tests** drive real `httptest` servers and decode real responses
  rather than mocking transport.

**Scope:** correctness of domain logic and every database contract in isolation, fast
and hermetic. This is the tier that should catch a regression first.

## Local data-plane e2e — `make e2e-local`

An **opt-in, in-tree, full-stack SSH connect test** in `warden/e2e`, guarded by the
`e2e` build tag and **excluded from `make ci`**. `make e2e-local` builds the Go
binaries (`go build`) and expects the Rust binaries under `target/debug`
(`cargo build --workspace`), then runs the whole SSH path against an ephemeral
Postgres and an in-test target `sshd`:

- It is **white-box** — it lives in the warden module, seeds state by direct DB
  writes, mints the mesh PKI with `warden-meshcert`, and reaches into internal test
  helpers — but it runs the **real `warden`, `gateway`, and `ssh-proxy` binaries as
  subprocesses** (not an in-process warden), then drives a real client tunnel:
  CLI tunnel → gateway `CONNECT` (external TLS) → ssh-proxy (mesh mTLS + SPIFFE pin)
  → `SetupSession` at warden → target `sshd` (SSH cert auth), round-tripping a
  command's output and exit code all the way back.

**Scope:** the data-plane wiring the unit tier can't reach — the gateway/worker/mesh
handshake, PASETO admission, credential injection, and recording mechanics — proven
against the actual binaries but **without** a Kubernetes cluster, so it stays fast.

## Cluster e2e — `make e2e-cluster`

A **black-box** end-to-end suite in `test/e2e` (its own Go module) that drives the
real **`jumpgate` CLI** and `kubectl` against a **live kind cluster** deployed from
the Helm chart (`deploy/helm/jumpgate`). `make e2e-cluster` brings up the cluster,
runs the suite with `JUMPGATE_E2E=1`, and tears the cluster down afterwards
(`KEEP=1` leaves it up). `make ci` never reaches this module.

**Scope:** the full governance flow through the **shipped artifacts** — a three-actor
cross-approval scenario: an admin onboards an SSH asset and a request policy; two
users request and approve each other's access; one connects and runs a command; an
admin auditor downloads the recording and confirms it captured the session. Where the
local tier proves the binaries wire together, this proves the *containers + Helm chart
+ CLI* deliver the same behavior, asserting even on recording **content**. The
narrated [walkthrough](demo/walkthrough.md) follows the same flow by hand.

## UI e2e — `make ui-e2e`

A **Playwright** suite (`web/e2e`, Nix-provided chromium) against the kind
environment where warden serves the embedded SPA. `make ui-e2e` brings up kind, seeds
fixtures through the CLI (`TestUISeed` in `test/e2e`: a JIT-requestable asset gated by
a cross-approval policy, plus a standing-access asset with a completed recording),
then runs the multi-actor browser story (`web/e2e/access-loop.spec.ts`) — alice
requests access, bob approves, alice sees her grant's connect command, and an admin
auditor plays the recording back — each actor in an isolated browser context. Opt-in,
kept out of `ci`.

**Scope:** the browser console's request → approve → connect → audit loop over the
same live stack the cluster tier uses, exercising the cookie-session auth and the SPA
views that the CLI-driven suites don't touch.

## Why the tiers stay complementary

Each tier owns a layer the others do not: unit/integration proves logic and every SQL
contract in isolation and runs on every change; local e2e proves the raw data-plane
binaries interoperate without the cost of a cluster; cluster e2e proves the shipped
containers, Helm chart, and CLI deliver the governance flow; UI e2e proves the browser
console over that same stack. Keep a new test at the **lowest tier that can prove it**
— push a rule into the unit/integration tier unless it genuinely requires the
data-plane binaries, the cluster, or the browser.
