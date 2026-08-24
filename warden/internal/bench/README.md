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
- **Macro** (`macro_test.go`, `macro_session_test.go`, `macro_write_test.go`) — real
  ConnectRPC service structs / internal services called in-process (the full handler →
  authz → SQL path). Covers catalog browse (BrowseFolder, GetAssetAccess,
  SearchCatalog), pending-approvals list, the session-runtime/revocation paths
  (CreateSession, Reevaluate, SweepOwned), and the mutating request/approval paths
  (RequestAccess, ApproveRequest).

Mutating benchmarks use `runWriteBench`: it pre-seeds `b.N` disposable targets (a
distinct eligible requester per RequestAccess, a distinct pending request per
ApproveRequest) OUTSIDE the timer and resets the query counter after seeding, so the
write path never trips a uniqueness/already-active guard and seeding never inflates
the metrics. Run these with a fixed `-benchtime` (e.g. `-benchtime=50x`) — `b.N`
drives how many targets are seeded.

## Reading the output

- **`queries/op`** is the N+1 detector. It should stay roughly constant as a profile
  scales; a value that climbs means a per-item query loop. Every operation now holds a
  constant count. `ListPendingApprovals` used to be the exception (`≈ 3 × PendingRequests
  + 1` from a per-request approver resolution); it was rewritten set-based to a single
  query (1 query/op) and the `PendingRequests` profile knob now serves as its regression
  guard — if that count ever climbs with pending volume again, the N+1 is back.
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
role-rewrite cascade, binding/policy fan-out, live-session count, and pending-request
count independently.

## Not yet covered

`SetupSession` (the worker↔gateway/proxy data-plane admission) is not yet benched.
Its fixture is heavy (SSH-CA/broker/minted-token/active-grant) and it also performs
CA key-signing work that is better benched in isolation than folded into the RPC
timing; the intent is to bench the warden↔worker RPC specifically. The
session-runtime layer currently covers `CreateSession` (client-side admission) plus
the revocation paths.
