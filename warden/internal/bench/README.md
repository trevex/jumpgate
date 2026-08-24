# warden benchmark suite

Opt-in benchmarks for warden's database-backed hot paths. Compiled only under the
`bench` build tag, so `go test ./...` and CI never run them. Requires the Nix
devshell's PostgreSQL tooling (`initdb`/`pg_ctl`/`createdb`); the suite boots one
throwaway cluster per run (via `TestMain`).

## Run

```
make bench                         # all benchmarks, all profiles
cd warden && go test -tags bench -run '^$' -bench BenchmarkCheck ./internal/bench/...
```

Environment knobs:

| Env | Effect |
|---|---|
| `BENCH_PROFILE=deep` | restrict to one profile (`wide`/`deep`/`dense-inheritance`/`balanced`) |
| `BENCH_SUMMARY=1` | write `bench-summary.md`, a table of (operation × profile) sorted by ns/op descending |
| `BENCH_JIT=on` | run with PostgreSQL JIT enabled (default off = production parity) to observe the JIT-compile pathology |
| `BENCH_EXPLAIN=1` | enable the on-demand `captureExplain` helper (writes `EXPLAIN (ANALYZE, BUFFERS)` plans to `bench-explain/`) |

## Layers

- **Micro** (`micro_test.go`) — authz/roleresolver/approvals methods called directly;
  isolates SQL + closure cost. Covers Check, CapabilitiesOnAsset/OnScope,
  VisibleFolders/Assets/Roles/GroupsUnder, EntitledLogins, HoldsRole(+Standing),
  IsApprover, IsEligibleRequester.
- **Macro** (`macro_test.go`, `macro_session_test.go`) — real ConnectRPC service
  structs / internal services called in-process (the full handler → authz → SQL
  path). Covers catalog browse (BrowseFolder, GetAssetAccess, SearchCatalog),
  pending-approvals list, and the session-runtime/revocation paths (CreateSession,
  Reevaluate, SweepOwned).

## Reading the output

- **`queries/op`** is the N+1 detector. It should stay roughly constant as a profile
  scales; a value that climbs with profile size means a per-item query loop —
  investigate. Every current operation holds a constant query count across profiles.
- **`ns/op`** is wall-clock per operation. A high ns/op with a *constant* query count
  points at row materialization/allocation cost rather than an N+1 (visible in the
  `B/op` / `allocs/op` columns from `-benchmem`).

## EXPLAIN plans

`captureExplain(tb, name, profile, sql, args...)` (in `explain.go`) runs
`EXPLAIN (ANALYZE, BUFFERS)` for a specific SQL statement and writes the plan under
`bench-explain/` when `BENCH_EXPLAIN=1`. It is an on-demand diagnostic: identify the
hot query from the timings, then call it with that query (or run the statement under
`psql`) to see the plan, the recursive-CTE row estimates, and any `JIT:` block.

## Profiles

Four named profiles (see `profile.go`) stress the folder tree, group nesting,
role-rewrite cascade, binding/policy fan-out, and live-session count independently.

## Not yet covered

`SetupSession` (the worker-side data-plane admission with the SSH-CA/broker/minted-
token/active-grant fixture) is not yet benched; the session-runtime layer currently
covers `CreateSession` (client-side admission) plus the revocation paths.
