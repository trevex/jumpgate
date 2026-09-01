# jumpgate

Just-in-time privileged access with zero standing credentials, fully audited. One
access model for SSH hosts, Postgres databases, and Kubernetes clusters — no permanent
credentials, and nothing to install on most targets.

A user requests the access they need, an approver grants it for a bounded window, the
credential is minted just in time and injected at the edge, and the session is recorded
end to end. When the grant expires or is revoked, any live session it backed is torn
down, not merely blocked at the next connect.

- **Zero standing credentials.** Nothing is granted until requested; grants are
  time-boxed and reaped, and losing access tears down live sessions.
- **Broad reach, light footprint.** An agentless proxy fronts SSH and Postgres;
  Kubernetes uses a lightweight in-cluster agent that dials out, so no inbound port is
  opened on a cluster.
- **Fully audited.** A hash-chained audit log plus per-protocol session recording (SSH
  terminal, Postgres statement log, Kubernetes API audit).

A Go control plane (the *warden*) holds all policy and secrets; a Rust and Go data
plane (the *gateway* and its SSH, Postgres, and Kubernetes workers) carries the traffic
and enforces at the edge. Access is driven by the `jumpgate` CLI or an embedded web
console.

## Development

Requires [Nix](https://nixos.org/download) (flakes enabled) and
[direnv](https://direnv.net). The devshell provides every other toolchain.

```sh
direnv allow      # or: nix develop
make ci           # gen + build + test + lint + web (what CI runs)
```

Run the whole stack on a local [kind](https://kind.sigs.k8s.io/) cluster and drive it
with the CLI:

```sh
make kind-demo    # cluster + chart + mesh CA + built ./jumpgate
```

See the [CLI walkthrough](docs/demo/walkthrough.md) for a three-actor request → approve
→ connect → audit tour.

## Documentation

Full docs are in [`docs/`](docs/) (rendered at
<https://trevex.github.io/jumpgate/>):
[architecture](docs/architecture.md) ·
[access model](docs/access-model.md) ·
[capabilities](docs/capabilities.md) ·
[security](docs/security.md) ·
[development](docs/development.md) ·
[roadmap](docs/roadmap.md).

## License

[GNU AGPL-3.0-only](LICENSE).
