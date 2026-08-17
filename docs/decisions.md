# Key decisions

The load-bearing architecture decisions and why we made them. Update this page
when a decision changes or a new one is made.

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backend split | Go control plane + Rust data plane | Go wins the k8s operator ecosystem, ReBAC engines, enterprise SSO, and team velocity; Rust wins proxy performance/safety and is uniquely strong for future RDP (IronRDP). |
| Data-plane shape | Two-tier: thin gateway + per-protocol workers | Independent per-protocol scaling and per-protocol *language* freedom (a future worker can be Go) behind one protocol-agnostic gateway. |
| Proxy posture | Agentless L7 gateway | Lowest adoption friction; best fit for the JIT / data-protection story. No software on targets. |
| Auth interaction | "Approach A" — control plane brokers, workers enforce | Security-critical state stays centralized in Go; workers are stateless and hold secrets only for a live session; revocation is immediate. |
| Access model | Custom Role + RoleBinding over OpenFGA | Enterprise-grade custom roles; the graph handles relationships (nested groups, folder inheritance), the control plane resolves roles → a fixed capability vocabulary. |
| Discoverability | Permission-gated (`requestable`) + 404-not-403 | Least privilege / need-to-know; asset existence is never leaked to unauthorized users. |
| Catalog visibility | Server-computed via the Authorizer; CodeNotFound for invisible assets | Discovery is permission-gated; asset existence never leaks to unauthorized users. |
| Postgres escalation | Inline per-statement approval + time-boxed tiered step-up | "Access when you need it" done robustly on a structured protocol; DB-enforced via `SET ROLE` (defense in depth). |
| SSH escalation | Pre-session only | Parsing commands from an interactive TTY is not a robust enforcement boundary; keep it honest. |
| Session token | PASETO v4.public (ed25519) | Simpler and more misuse-resistant than JWT. |
| Identity (MVP) | Local accounts first | Fastest to iterate; OIDC/SAML/SCIM is a later sub-project. |
| Authz engine | `Authorizer` seam + roll-our-own Postgres/recursive-CTE backend (M2a) | Our model (nested groups, folder inheritance, standing/requestable tiers) maps cleanly to recursive SQL CTEs; avoids OpenFGA's heavy in-process footprint (~59 deps, separate store). OpenFGA (embedded or sidecar) remains a drop-in behind the seam. |
| Data layer | sqlc + pgx/v5 + goose (embedded migrations) | Type-safe SQL without ORM magic; migrations embedded in the binary; tests run against an ephemeral Postgres (initdb/pg_ctl), no Docker. |
| API layer | ConnectRPC (connect-go) over buf; opaque DB-backed bearer tokens | One proto contract for browser + CLI + future Rust gRPC workers, no Envoy; protovalidate for validation; CodeNotFound hides non-visible resources; tokens are revocable server-side (not JWT). |
| CLI language | Go (cobra) | Shares the API client; clean static cross-compiles. |
| Frontend | React + Vite SPA embedded in the backend binary | Matches the Teleport/hoop pattern; largest ecosystem for data-heavy admin UIs. |
| Dev environment | Nix flake devshell + direnv | One pinned, reproducible toolchain across contributors and CI. |
| Audit integrity | Hash-chained append-only log | Tamper-evident; standard, auditor-accepted mechanism. |

## Notable non-choices (deferred by design)

- **RDP, Kubernetes, MySQL/Mongo, HTTP/API proxying** — later sub-projects; the
  two-tier data plane is designed so each is an additive worker.
- **Inline DLP / command blocking** and **AI-agent/MCP governance** — differentiation
  bets deferred until the core is proven.
- **HA / multi-region** — out of MVP scope.
