# jumpgate documentation

Technical documentation for jumpgate — an enterprise, agentless, JIT-first
Privileged Access Management (PAM) platform.

These docs are **living documentation**: every milestone updates them to reflect
what is actually built. Each page states which parts are implemented today versus
planned, so the docs never drift from the code.

> Note: `docs/superpowers/` (brainstorming specs, implementation plans) is a
> separate, gitignored area for workflow artifacts. It is **not** project
> documentation — the durable technical docs live here, directly under `docs/`.

## Contents

| Page | What it covers |
|------|----------------|
| [architecture.md](architecture.md) | System design: control plane, two-tier data plane, access model, JIT/approvals, audit |
| [access-model.md](access-model.md) | Conceptual reference: how groups, folders, assets, roles, bindings & approval rules interact (with worked examples) |
| [capabilities.md](capabilities.md) | The capability vocabulary: scoped `scope:action[:qualifier]` grammar, glob matching, and the warden-decides / worker-enforces split |
| [data-model.md](data-model.md) | Schema/entity reference: core tables, key columns, relationships, and an ER diagram (derived from the migrations) |
| [security.md](security.md) | Consolidated security posture & threat model (existence-hiding, token model, continuous revocation, audit, secrets) |
| [development.md](development.md) | Getting started: Nix devshell, repo layout, codegen, testing, CI conventions |
| [roadmap.md](roadmap.md) | Milestone plan (M1–M7) and current status |
| [decisions.md](decisions.md) | Key architecture decisions and their rationale |

## Documentation conventions

- **Keep it current.** When a milestone changes behavior, update the relevant
  page in the same change. Treat stale docs as a bug.
- **Mark status.** When describing a component, note whether it is *implemented*,
  *partial*, or *planned* so readers can trust the page.
- **Link, don't duplicate.** Cross-reference between pages instead of repeating
  content.
