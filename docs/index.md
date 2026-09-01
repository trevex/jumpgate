---
icon: lucide/rocket
title: jumpgate documentation
description: Just-in-time privileged access with zero standing credentials, fully audited.
---

<div class="jg-hero" markdown>

# jumpgate

<p class="jg-tagline" markdown>
Just-in-time privileged access with zero standing credentials, fully audited.
One access model for SSH hosts, Postgres databases, Kubernetes clusters, and RDP
desktops — no permanent credentials, and nothing to install on most targets.
</p>

[Get started :material-arrow-right:](development.md){ .md-button .md-button--primary }
[Architecture](architecture.md){ .md-button }

</div>

Privileged access is where breaches start: standing credentials that outlive their
purpose, shared admin accounts nobody can attribute, and sessions no one reviews.
jumpgate removes the standing access. A user requests the access they need, an approver
grants it for a bounded window, the credential is minted just in time and injected at
the edge, and the whole session is recorded. When the grant expires or is revoked, any
live session it backed is torn down — not merely blocked at the next connect.

A Go control plane (the *warden*) holds all the policy and secrets; a Rust and Go data
plane (the *gateway* and its protocol workers) carries the traffic and enforces at the
edge. The result is one governance model — request, approve, connect, audit — that
spans a shell, a database, and a cluster.

## What jumpgate is

<div class="grid" markdown>

:material-clock-fast: __Zero standing credentials__
{ .card }

Nothing is granted until it is requested. A request is approved, a grant is minted with
a lifetime, and a reaper tears it down — live sessions included — the moment eligibility
ends. No permanent keys, no shared accounts.

:material-lan-connect: __Broad reach, light footprint__
{ .card }

An agentless network proxy fronts SSH, Postgres, and RDP, so onboarding a target is a
catalog entry rather than a rollout. Kubernetes uses a lightweight in-cluster agent
that dials out, so no inbound port is opened on a cluster.

:material-file-document-check: __Fully audited__
{ .card }

Every decision, session, and keystroke is attributable: a transactional audit outbox
plus session recording — SSH terminal, Postgres statement log, Kubernetes API audit,
RDP graphics stream — reviewable by the grant subject and its approvers.

</div>

## Explore the docs

<div class="grid cards" markdown>

-   :material-sitemap: __Architecture__

    ---

    The control plane, the data plane (gateway plus SSH, Postgres, Kubernetes, and RDP
    workers), the credential vault, audit and recording, and how a session flows end to
    end.

    [:octicons-arrow-right-24: Read](architecture.md)

-   :material-account-key: __Access model__

    ---

    Groups, folders, assets, roles, standing bindings, and request policies. The
    Active / Requestable / Invisible tiers and the request → approve → grant → reaper
    workflow, with worked examples.

    [:octicons-arrow-right-24: Read](access-model.md)

-   :material-format-list-checks: __Capabilities__

    ---

    The `scope:action[:qualifier]` grammar, glob matching, the management-plane and
    data-plane vocabularies, and the warden-decides / worker-enforces split.

    [:octicons-arrow-right-24: Read](capabilities.md)

-   :material-database: __Data model__

    ---

    The Postgres tables, key columns, constraints, and how they relate, with an ER
    diagram.

    [:octicons-arrow-right-24: Read](data-model.md)

-   :material-shield-lock: __Security__

    ---

    Existence-hiding, the token model, account deactivation, continuous revocation,
    audit integrity, and secrets-at-rest — the consolidated posture and threat model.

    [:octicons-arrow-right-24: Read](security.md)

-   :material-tools: __Development__

    ---

    Nix devshell, repo layout, codegen, the data layer, the vertical-slice domain/RPC
    pattern, and CI conventions.

    [:octicons-arrow-right-24: Read](development.md)

-   :material-test-tube: __Testing__

    ---

    The test tiers — in-package unit/integration, cluster e2e, and UI e2e — what each
    proves and how they stay complementary.

    [:octicons-arrow-right-24: Read](testing.md)

-   :material-play-circle: __Demo walkthroughs__

    ---

    Drive the real CLI and the web console through a three-actor cross-approval
    scenario, end to end.

    [:octicons-arrow-right-24: CLI](demo/walkthrough.md) ·
    [Web console](demo/walkthrough-ui.md)

</div>

---

!!! tip "Documentation conventions"

    These pages describe how jumpgate works today.

    - Describe the system as it is. A change that alters behavior updates the relevant
      page in the same change.
    - Mark what is planned. Defined-but-unbuilt components say so plainly, so the docs
      never overstate what exists.
    - Link, don't duplicate. Pages cross-reference instead of repeating.
