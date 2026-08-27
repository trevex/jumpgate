---
icon: lucide/rocket
title: jumpgate documentation
description: Enterprise, agentless, just-in-time Privileged Access Management.
---

<div class="jg-hero" markdown>

# jumpgate

<p class="jg-tagline" markdown>
**Enterprise, agentless, just-in-time Privileged Access Management.**
A Go control plane (the *warden*) and a Rust data plane (the *gateway* and protocol
workers) that grant time-boxed, fully audited access to infrastructure — with no
standing credentials and no agent to install on targets.
</p>

[Get started :material-arrow-right:](development.md){ .md-button .md-button--primary }
[Architecture](architecture.md){ .md-button }

</div>

These pages describe how jumpgate works **today**. Where a capability is defined but
not yet built, the page says so and marks it planned — so the docs never overstate
what exists.

## Explore the docs

<div class="grid cards" markdown>

-   :material-sitemap: __Architecture__

    ---

    The control plane, the two-tier data plane (gateway + protocol workers), the
    credential vault, audit & recording, and how a session flows end to end.

    [:octicons-arrow-right-24: Read](architecture.md)

-   :material-account-key: __Access model__

    ---

    Groups, folders, assets, roles, standing bindings & request policies — the
    Active / Requestable / Invisible tiers and the request → approve → grant → reaper
    workflow, with worked examples.

    [:octicons-arrow-right-24: Read](access-model.md)

-   :material-format-list-checks: __Capabilities__

    ---

    The `scope:action[:qualifier]` grammar, glob matching, the management- and
    data-plane vocabularies, and the warden-decides / worker-enforces split.

    [:octicons-arrow-right-24: Read](capabilities.md)

-   :material-database: __Data model__

    ---

    The Postgres tables, key columns, constraints and how they relate, with an ER
    diagram.

    [:octicons-arrow-right-24: Read](data-model.md)

-   :material-shield-lock: __Security__

    ---

    Existence-hiding, the token model, account deactivation, continuous revocation,
    audit integrity, and secrets-at-rest — the consolidated posture & threat model.

    [:octicons-arrow-right-24: Read](security.md)

-   :material-tools: __Development__

    ---

    Nix devshell, repo layout, codegen, the data layer, the vertical-slice
    domain/RPC pattern, and CI conventions.

    [:octicons-arrow-right-24: Read](development.md)

-   :material-test-tube: __Testing__

    ---

    The test tiers — in-package unit/integration, local data-plane e2e, cluster e2e
    and UI e2e — what each proves and how they stay complementary.

    [:octicons-arrow-right-24: Read](testing.md)

-   :material-play-circle: __Demo walkthroughs__

    ---

    Drive the real CLI and the web console through a three-actor cross-approval
    scenario, end to end.

    [:octicons-arrow-right-24: CLI](demo/walkthrough.md) ·
    [Web console](demo/walkthrough-ui.md)

</div>

## What jumpgate is

<div class="grid" markdown>

:material-shield-account: __Agentless__
{ .card }

Targets need no installed agent. Access flows through the gateway and protocol
workers, so onboarding an asset is a catalog entry, not a rollout.

:material-clock-fast: __Just-in-time__
{ .card }

No standing credentials. A request is approved, a grant is minted with a lifetime,
and a reaper tears it down — live sessions included — the moment eligibility ends.

:material-file-document-check: __Fully audited__
{ .card }

Every decision, session and keystroke is attributable: a transactional audit outbox
plus session recording, reviewable by the grant subject and its approvers.

</div>

---

!!! tip "Documentation conventions"

    - **Describe the system as it is.** These pages document current behavior; a
      change that alters behavior updates the relevant page in the same change.
    - **Mark what is planned.** Defined-but-unbuilt components say so plainly.
    - **Link, don't duplicate.** Pages cross-reference instead of repeating.
