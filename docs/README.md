# jumpgate documentation

Technical documentation for jumpgate — an enterprise, agentless, just-in-time (JIT)
Privileged Access Management (PAM) platform.

These pages describe how jumpgate works today. Where a capability is not yet built
(other protocols, the web UI, enterprise SSO), the page says so explicitly and
marks it as planned, so the docs never overstate what exists.

> Note: `docs/superpowers/` (brainstorming specs, implementation plans) is a
> separate, gitignored area for workflow artifacts. It is **not** project
> documentation — the durable technical docs live here, directly under `docs/`.

## Contents

| Page | What it covers |
|------|----------------|
| [architecture.md](architecture.md) | System design: the control plane, the two-tier data plane (gateway + protocol workers), the credential vault, audit & recording, and how a session flows end to end |
| [access-model.md](access-model.md) | Conceptual reference: how groups, folders, assets, roles, standing bindings & request policies decide who can do what, where — the Active/Requestable/Invisible tiers and the request→approve→grant→reaper workflow, with worked examples |
| [capabilities.md](capabilities.md) | The capability vocabulary: the `scope:action[:qualifier]` grammar, glob matching, the management-plane and data-plane vocabularies, and the warden-decides / worker-enforces split |
| [data-model.md](data-model.md) | Schema/entity reference: the Postgres tables, key columns, constraints, and how they relate, with an ER diagram |
| [security.md](security.md) | Consolidated security posture & threat model: existence-hiding, the token model, account deactivation, continuous revocation, audit integrity, and secrets-at-rest |
| [development.md](development.md) | Getting started: Nix devshell, repo layout, codegen, data layer, testing, CI conventions |
| [roadmap.md](roadmap.md) | What is built and what is planned next |
| [decisions.md](decisions.md) | The load-bearing architecture decisions and their rationale |

## Documentation conventions

- **Describe the system as it is.** These pages document current behavior. When a
  change alters behavior, update the relevant page in the same change; treat stale
  docs as a bug.
- **Mark what is planned.** When a component or verb is defined but not yet built,
  say so plainly so readers can trust the page.
- **Link, don't duplicate.** Cross-reference between pages instead of repeating
  content.
