# Testing

jumpgate is tested in tiers, each aimed at a different layer so their coverage stays
complementary rather than redundant. Read this alongside the quick command reference in
[development.md](development.md#testing).

| Tier | Command | In CI? | Where | Proves |
|---|---|---|---|---|
| In-package unit and integration | `go test ./...` (via `make test`) plus `cargo nextest` | ✅ yes | `warden/`, `cli/`, workers, `gateway/` | domain logic, SQL/sqlc queries, the authz functions, handlers |
| Cluster e2e | `make e2e-cluster` | ❌ opt-in | `test/e2e` | the shipped containers, CLI, and Helm deliver the governance flow for SSH, Postgres, and Kubernetes |
| UI e2e | `make ui-e2e` | ❌ opt-in | `web/e2e` | the browser console over the live stack |

`make ci` runs `make test` (plus `cargo nextest` and the web typecheck and build), so the
first tier is the everyday correctness gate; the two e2e tiers are opt-in and kept out of
`ci`.

## In-package unit and integration — the primary gate

`make test` runs `go test ./...` across the `warden`, `cli`, and worker modules (plus
`cargo nextest` for the Rust workspace and the web typecheck and build). This is what
`make ci`, and therefore CI, runs.

- Unit tests cover pure logic: capability matching and normalization, scope derivation,
  the pagination codec, path helpers, error mapping. `TestSQLCapMatchMatchesGo` pins the
  three-column SQL capability match equal to the Go `CapMatch` glob.
- `workers/rdp-proxy` is its own Cargo workspace, excluded from the root
  `Cargo.toml` because `ironrdp-connector` pins a `curve25519-dalek` version that
  conflicts with ssh-proxy's `russh` (see `Cargo.toml`). `cargo nextest run
  --workspace` therefore does not reach it; its unit tests run with `cargo test
  --manifest-path workers/rdp-proxy/Cargo.toml`.
- Integration tests boot a real, ephemeral PostgreSQL through
  `internal/testsupport.StartPostgres`, which uses the devshell's `initdb` and `pg_ctl`
  (no Docker) and tears the server down at test end. They `t.Skip` when that tooling is
  not on `PATH`, so run them inside `nix develop`; in CI the devshell provides it, so they
  execute. These tests exercise the sqlc queries and the `authz_*` SQL functions against
  the real migrated schema, including the drift and guard tests
  (`internal/authz/authz_functions_test.go` and `no_raw_closure_sql_test.go`, which fails
  the build if closure SQL is hand-written in Go).
- HTTP and handler tests drive real `httptest` servers and decode real responses rather
  than mocking transport.

Scope: correctness of domain logic and every database contract in isolation, fast and
hermetic. This is the tier that should catch a regression first.

## Cluster e2e — `make e2e-cluster`

A black-box end-to-end suite in `test/e2e` (its own Go module) that drives the real
`jumpgate` CLI and `kubectl` against a live kind cluster deployed from the Helm chart
(`deploy/helm/jumpgate`). `make e2e-cluster` brings up the cluster, runs the suite with
`JUMPGATE_E2E=1`, and tears the cluster down afterwards (`KEEP=1` leaves it up). `make ci`
never reaches this module.

Scope: the full governance flow through the shipped artifacts — the containers, Helm chart,
and CLI, asserting even on recording content. The suite covers:

- `TestScenario` — a three-actor cross-approval walkthrough over SSH: an admin onboards
  assets (all three SSH auth kinds) and a request policy; two users request and approve
  each other's access; one connects and runs a command; an auditor downloads the recording
  and confirms it captured the session. It also exercises delegated folder administration.
- `TestPostgresPassword` and `TestPostgresMtls` — a user connects to a Postgres asset
  through the loopback proxy (password and mTLS logins), runs a query, and the suite
  confirms a completed statement-log recording containing the query.
- `TestKubernetes` — an admin onboards a cluster and captures the enrollment token, the
  agent enrolls and dials the broker, a user granted `k8s:group:developers` runs `kubectl`
  through jumpgate: `get pods` succeeds, `get secrets -n kube-system` is Forbidden, and the
  API-audit recording captures both outcomes.
- `TestAuthzVisibility` and `TestAuthzGrantTransitions` — steady-state tenant isolation
  and the load-bearing check that each authz primitive denies before it is granted, so a
  default-open regression fails the suite.

RDP has no CLI connect path — it is browser-only — so this Go-driven tier does not cover
it; its governance flow is instead exercised end to end by the UI e2e tier below.

Where the unit tier proves the binaries in isolation, this proves the whole shipped stack
delivers the same behavior. The narrated [walkthrough](demo/walkthrough.md) follows the
same flows by hand.

## UI e2e — `make ui-e2e`

A Playwright suite (`web/e2e`, Nix-provided chromium) against the kind environment where
warden serves the embedded SPA. `make ui-e2e` brings up kind, seeds fixtures through the
CLI (`TestUISeed` in `test/e2e`: a JIT-requestable asset gated by a cross-approval policy,
plus a standing-access asset with a completed recording), then runs the multi-actor browser
story (`web/e2e/access-loop.spec.ts`) — alice requests access, bob approves, alice sees her
grant's connect command, and an admin auditor plays the recording back — each actor in an
isolated browser context. Opt-in, kept out of `ci`.

`web/e2e/rdp.spec.ts` separately proves the RDP round trip: alice opens the seeded
`rdp-box` asset's **Open RDP** link, and the test asserts a canvas renders and the
`jumpgate-rdp` WASM client actually processes a graphics frame — browser through the
gateway, the rdp-proxy worker, and the target xrdp server.

Scope: the browser console's request → approve → connect → audit loop over the same live
stack the cluster tier uses, exercising the cookie-session auth and the SPA views the
CLI-driven suites do not touch.

## Why the tiers stay complementary

Each tier owns a layer the others do not: unit and integration prove logic and every SQL
contract in isolation and run on every change; cluster e2e proves the shipped containers,
Helm chart, and CLI deliver the governance flow across all three protocols; UI e2e proves
the browser console over that same stack. Keep a new test at the lowest tier that can prove
it — push a rule into the unit and integration tier unless it genuinely requires the
cluster or the browser.
