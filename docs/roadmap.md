# Roadmap

The MVP (Sub-project #1: **SSH + Postgres + JIT core**) is built as a sequence of
milestones, each producing working, testable software. Later product sub-projects
follow the MVP.

## MVP milestones

| Milestone | Scope | Status |
|-----------|-------|--------|
| **M1** | Foundation & scaffolding — Nix devshell, Go+Rust workspaces, protobuf codegen, control-plane + gateway health binaries, CI | ✅ Done |
| **M2** | Access-model core — users/groups/folders/assets, custom Role + RoleBinding over OpenFGA, visibility tiers, catalog/CRUD REST | 🟡 In progress (M2a done: data + authorizer core; M2b: REST/catalog) |
| **M3** | JIT + vault + audit — access requests, approval engine, time-boxed grants + reaper, credential vault, hash-chained audit | ⬜ |
| **M4** | Gateway + ssh-proxy + CLI — worker registry, session routing/LB, `jumpgate connect <ssh>` end-to-end with injection + recording | ⬜ |
| **M5** | pg-proxy + inline step-up — Postgres access, per-statement approval, tiered `SET ROLE` step-up | ⬜ |
| **M6** | Web UI — embedded SPA, admin console, approvals, xterm.js terminal, web SQL console | ⬜ |
| **M7** | Deploy — Helm chart + docker-compose packaging | ⬜ |

## Beyond the MVP (later product sub-projects)

| # | Sub-project | Adds |
|---|-------------|------|
| 2 | Enterprise identity | OIDC/SAML SSO, SCIM group sync |
| 3 | RDP + more databases | IronRDP (Rust), MySQL/Mongo, browser RDP |
| 4 | Kubernetes access | k8s API proxy + impersonation + audit |
| 5 | k8s operator / CRDs | Declarative assets/roles/policies via a Go controller |
| 6 | Generic HTTP/API + inline DLP | Web-app proxy, PII masking, command/query blocking, ChatOps approvals, SIEM export |

## Carried-forward items (address as their milestone opens)

These were surfaced during M1 review and are intentionally deferred:

- **Graceful shutdown** in both binaries (Go `http.Server.Shutdown` + signal; Rust
  `tokio::signal`) — needed **before M2** opens persistent DB/gRPC connections.
- **CI Nix caching** (e.g. magic-nix-cache / Cachix) — before CI runtime becomes painful.
- **Explicit `.golangci.yml`** — pin the linter set before real app code lands.
- **Second Go module (`cli`) coverage** in the Makefile's Go targets (M4).
