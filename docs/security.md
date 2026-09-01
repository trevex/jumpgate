# Security & threat model

The consolidated security posture of jumpgate: what it defends and how. This page
references the detailed treatments elsewhere ([access-model.md](access-model.md),
[architecture.md](architecture.md), [capabilities.md](capabilities.md),
[decisions.md](decisions.md)) rather than duplicating them. Where a defense applies
only to a protocol that is not yet built, it says so.

## Posture — what we defend

- Zero standing credentials. Access is requestable, approval-gated, and JIT
  time-boxed. Nothing is standing unless an admin binds it, and a role is requestable
  only where a RequestPolicy exists and the caller is eligible (holds a
  `requester_role` on the scope via a standing binding, or is a named `requester`
  subject). The approval gate travels with the role. The workflow is request → N-of-M
  approve (self-service at `required_approvals=0`) → a time-boxed `access_grants` row
  that authorizes like a standing binding until its `expires_at` or revoke → a reaper.
  Grant lifetime is clamped to `min(requested, policy.max_duration, MaxGrantTTL=8h)`.
  See [access-model.md](access-model.md#approval--who-signs-off-and-how-a-request-activates).
- Grants confer access, not governance. A role obtained via a JIT `access_grant` gives
  real access (it joins the `HoldsRole` held closure) but is excluded from the
  requester and approver predicates, which resolve standing-only (`HoldsRoleStanding`).
  A granted `requester_role` or `approver_role` can never be used to request or approve
  further access, closing self-escalation loops.
- Minimal footprint on targets. SSH and Postgres run through an agentless L7 proxy: no
  software is installed on the target host, and the worker terminates the protocol and
  injects a short-lived credential at the edge. Kubernetes uses a lightweight agent
  that runs inside the target cluster and dials out over mesh mTLS, so jumpgate opens
  no inbound port on a cluster and holds no long-lived cluster credential.
- Centralized security-critical state. The vault, policy, and grants live in warden
  (Go). A data-plane worker holds a credential only for the life of one authorized
  session.

## Existence-hiding — topology never leaks

Discoverability is itself a permission. `ListAssets` and `ListFolders` return only the
nodes a caller can see (Active ∪ Requestable, or manageable). A direct lookup of an
invisible asset returns `CodeNotFound`, never `CodePermissionDenied`, so an attacker
cannot map infrastructure by probing for `403`s. Browsing an unrelated folder path
also returns `CodeNotFound`. The same NotFound-hiding applies to `Resolve*` for
folders, roles, groups, and policies. See the visibility tiers in
[access-model.md](access-model.md#requestable-eligibility--visibility-tiers--what-can-i-see-or-ask-for).

## AuthN & token model

Three distinct token mechanisms:

- API bearer tokens (CLI). `AuthService.Login` with `cookie_only=false` (the default)
  exchanges email and password for an opaque, DB-backed, hashed bearer token, not a
  JWT. Passwords are hashed with argon2id; the token is stored hashed
  (`auth_tokens.token_hash`) with a 12-hour expiry, returned in the response body, and
  presented as `Authorization: Bearer <token>`. Because the server holds the token
  record, revocation is instant and server-side (delete the row). The CLI stores the
  token in `~/.config/jumpgate/config.json` per named context.

- Browser cookie sessions. `Login` with `cookie_only=true` issues the same opaque token
  but delivers it via a `Set-Cookie` response header instead of the body (the response
  body `token` field is empty). The cookie is `jumpgate_session`, `HttpOnly` (JS cannot
  read it), `SameSite=Strict`, `Secure` by default (set `JUMPGATE_COOKIE_INSECURE=true`
  for dev over plain HTTP), with `MaxAge` matching the token's 12-hour TTL.

  CSRF defense. The auth interceptor accepts a cookie credential only when the request
  also carries `Sec-Fetch-Site: same-origin`. Browsers set this header automatically
  for same-origin fetches and cannot be instructed by JavaScript to forge it on a
  cross-origin request, so a third-party page that tricks the browser into sending the
  cookie still cannot authenticate. Requests without the header are treated as
  unauthenticated (the cookie is ignored, not rejected). Bearer tokens are never
  CSRF-restricted; the CLI never sends `Sec-Fetch-Site`.

- Session admission tokens. The short-lived token that admits a data-plane session is a
  separate mechanism: a PASETO v4.public token (Ed25519), minted by `CreateSession` (or
  the Postgres, Kubernetes, and web variants) and verified offline by the gateway. The
  SSH token is bound to the client's ephemeral key fingerprint (`cnf`); the Postgres
  and Kubernetes tokens are bearers, and the Kubernetes token also carries the caller's
  email, group set, and the resolved `broker_id`. The signing key is DB-backed and
  sealed at rest. This is what lets the externally-exposed gateway authorize a
  connection without a round-trip to warden, while the worker still re-authorizes at
  session setup.

### Logout

`AuthService.Logout` requires authentication and revokes the caller's current token
server-side (idempotent). When the token was supplied via cookie it also clears the
`jumpgate_session` cookie (by setting `MaxAge=-1` in the response).

### WhoAmI

`AuthService.WhoAmI` returns the caller's `user_id`, `email`, `display_name`, and a
`capabilities` list of the globally-held capability patterns — the set `Check` would
resolve for the user across the global scope. This is the UI nav-gating signal: the
SPA calls `WhoAmI` on load and uses the list to decide which sections to show.

### Browser dev note

In a browser UI served by a Vite dev server the browser sees warden as the same origin
(Vite proxies `/api` to `localhost:8080`), so `cookie_only` login and the
`Sec-Fetch-Site: same-origin` CSRF gate work without any CORS configuration.

For a setup where the browser must reach warden cross-origin (for example a
separate-host dev environment), set `JUMPGATE_DEV_CORS_ORIGINS` to a comma-separated
list of allowed origins. This enables CORS headers on matching requests
(`Access-Control-Allow-Credentials: true`, `Vary: Origin`, and a preflight handler for
`OPTIONS`). The CORS middleware is a no-op when the list is empty (the default), which
is correct for production where the SPA is served same-origin. Cross-origin requests
from a browser cannot carry `Sec-Fetch-Site: same-origin`, so a separate-host dev setup
should use bearer tokens (`cookie_only=false`) rather than cookie sessions.

## Capability enforcement boundary

Capabilities are format-validated at role creation (protovalidate) and are opaque
tokens to warden. warden decides (it resolves held roles → capability set → yes/no via
`Check` / `CapMatch`); enforcement happens in two places:

- Management plane — warden enforces directly in each RPC handler (`requireCap` at the
  relevant scope). This replaced the old boolean `is_admin` gate: there is no admin
  flag, only capabilities.
- Data plane — the worker enforces protocol semantics at a live session (mapping a
  protocol operation to a capability, checking it, and configuring the access). Live
  for SSH (`ssh:*`), Postgres (`db:login:*`), and Kubernetes (`k8s:group:*`). Finer
  Postgres per-statement tiers (`db:read` / `db:write` / `db:ddl`) are defined for the
  model; per-statement step-up enforcement is not built.

See [capabilities.md](capabilities.md#where-enforcement-lives--warden-decides-workers-enforce).
A Kubernetes safety property is worth restating: because groups are enumerated rather
than glob-matched, `**` and `k8s:group:*` grant no groups, so a jumpgate admin holding
`**` is deliberately not cluster-admin. See
[capabilities.md](capabilities.md#kubernetes-holding-a-group-is-the-gate-and--is-not-cluster-admin).

## Account deactivation

`users.deactivated_at` (NULL means active) is an immediate off-switch for a principal,
enforced at three layers:

- Login (`AuthService.Login`): a deactivated account cannot mint a new token — login
  fails with `CodeUnauthenticated`.
- Auth interceptor: on every authenticated RPC the resolved user is re-checked; if
  `deactivated_at` is set the load fails and the call is `CodeUnauthenticated`, even
  with an otherwise-valid, unexpired token.
- Authorization closures: every authz query filters `deactivated_at IS NULL`, so a
  deactivated user holds nothing and counts for nothing — not in their own `HoldsRole`
  closure, and not as an approver, `requester_role` or `approver_role` holder, or
  contributor to anyone else's closure via group membership or a named policy subject.
  Deactivation also cascades to JIT grants: `DeactivateUser` revokes the user's active
  `access_grants` (reason `user_deactivated`), each audited and routed to teardown, so
  their live sessions are torn down.

So deactivation is a complete, reversible off-switch (reactivate with `ReactivateUser`,
or hard-`DeleteUser` with FKs cascading). It stops the principal from authenticating or
acting and removes them from everyone's resolution, without deleting their bindings,
memberships, or audit history.

## Continuous enforcement — revocation tears down live sessions

Authorization is continuous, not connect-time only: revoking a permission terminates
any live session that depended on it, not just blocks the next connect. Because the
held closure filters `revoked_at IS NULL AND expires_at > now()`, a revoked or expired
grant stops conferring access immediately, and the live session it supported is
force-closed by warden signalling the owning worker.

Every revocation source below re-evaluates the affected sessions and tears down those
no longer permitted, each audited (`session.terminated`, alongside the revocation
event):

| Revocation source | Who or what | Authorized for |
|---|---|---|
| Grant expiry | the in-process reaper (`ReaperInterval`, 30s) sweeps grants past `expires_at`, sets `revoked_reason='expired'` | automatic (system) |
| Manual `RevokeGrant` | an explicit revoke of one grant | a holder of `access:grant:revoke`, the grant's subject (self-revoke), or any standing approver for its (role, asset) |
| Deactivation | `DeactivateUser` revokes the user's active grants | the deactivation actor |
| Standing-authz change | a deleted role binding, a removed group membership, a changed role-rewrite rule, or a dropped role capability | the admin who made the change |

Detection is push plus pull: a Postgres `authz_changed` notification drives
near-instant re-evaluation, and a periodic ownership-partitioned sweep (debounced) is
the level-triggered backstop; an orphan GC reconciles unreachable workers and stuck
teardowns off a worker-presence heartbeat. Full treatment in
[architecture.md](architecture.md#continuous-revocation--live-session-teardown).

## Tamper-evident audit

Every security-relevant event is appended to a hash-chained, append-only audit log:
`entry_hash = sha256(prev_hash ‖ canonical(entry))`, so any after-the-fact edit or
deletion breaks the chain and is detectable (`Verify`).

Durability — transactional outbox. The audit logger's direct `Append` opens its own
advisory-locked transaction and cannot enlist in a domain transaction, so a post-commit
append would leave a crash window between the domain commit and the append.
State-changing services (the JIT request, approve, deny, cancel, and grant paths; the
reaper; session setup and teardown) instead enqueue each event into an `audit_outbox`
row inside the same domain transaction: the event and the action it records commit
atomically or not at all. If the enqueue fails, the whole transaction rolls back, so
there is no silent gap. A background drainer moves outbox rows into the hash-chained
`audit_log` in one advisory-locked transaction, chaining then deleting each row
together, so delivery is exactly-once and re-drains safely after a crash.

One event is deliberately not on the outbox: the vault's `credential.issued`
(`Broker.Issue`) is a genuinely post-fact append — the certificate is already minted
and returned, with no domain transaction to enlist in — so it uses direct `Append`. Its
narrow crash window is benign (a re-issue is harmless).

## Session recording

Sessions are recorded by default, in a per-protocol format, streamed to S3-compatible
object storage with a rolling SHA-256. Recording is fail-closed, and admin retrieval is
presigned and audited (`recording.accessed`).

- SSH: asciicast v2, capturing both directions of terminal I/O plus resizes with
  timing. A required recording that cannot be established, or a mid-session write
  failure, refuses or tears down the session. The one exemption is a subject holding
  `ssh:record:exempt` on the asset.
- Postgres: `pgwire-timeline-v1` NDJSON, one event per client statement plus command
  tags and errors. The client→target pump decodes every statement before forwarding, so
  a recorder failure kills the session before an un-recorded statement reaches the
  target. Bind-parameter values and result rows are redacted (the timeline records that
  a query ran, not the data it touched). There is no record-exempt path for Postgres.
- Kubernetes: `k8s-audit-v1` NDJSON, one event per API request (verb, resource,
  namespace, name, groups, status). Recording is per connection, and the broker refuses
  to start without a recording bucket. There is no record-exempt path for Kubernetes.

A web replay player exists for all three formats. SIEM export is planned.

## Secrets at rest

The vault envelope-encrypts every secret it holds — CA private keys, the
session-signing key, and stored target secrets. Each secret gets a fresh random 256-bit
DEK that encrypts the plaintext (AES-256-GCM); the DEK is then wrapped by a master KEK
(also AES-256-GCM). Plaintext never touches the DB unsealed, and sealed bytes are never
returned via the API — decryption happens only inside the broker to hand a credential
to a worker for a live, authorized session. GCM makes it fail-closed: a wrong KEK or a
tampered blob fails `Open`. See [architecture.md](architecture.md#vault--credentialbroker).

- Master-key custody. The KEK is a base64 32-byte `VAULT_MASTER_KEY` (env for now; a
  KMS is the future seam — only the DEK-wrap step changes, so master-key rotation
  re-wraps DEKs without touching ciphertexts). The vault is disabled (fail-closed, warn
  at boot) if the key is unset, and fatal if malformed.
- Losing the master key loses all sealed secrets. There is no recovery path, since the
  DEKs are wrapped under it. Custody of `VAULT_MASTER_KEY` (or the future KMS key) is a
  top-tier operational secret.

Short-lived, capability-scoped credentials. The credential the broker mints is bounded
by the granting authorization: `SetupSession` passes the remaining lifetime into the
cert's `ValidBefore` (or the secret's validity), so a credential never outlives the
access behind it. For SSH the cert's principals are capability-derived and host-scoped:
the broker mints only the logins the user holds `ssh:login:<login>` for, as
`<login>@<asset>` principals, with no static host login. For Postgres the `mtls` kind
mints a short-lived X.509 client cert whose CN is the DB role, and the `password` kind
returns the sealed stored password; both are gated by `db:login:<role>`. An empty SSH
entitlement is refused, and the SSH CA independently refuses to sign a principal-less
cert. Every issuance appends `credential.issued`. See
[access-model.md](access-model.md#ssh-access--os-logins-are-capabilities).

## Kubernetes agent trust

The Kubernetes agent runs inside a customer cluster, so its trust boundary is worth
stating explicitly.

- Enrollment is single-use and hashed. An admin holding `catalog:asset:update` mints an
  enrollment token bound to the asset; warden stores only its SHA-256 hash with a
  30-minute TTL, and `SignAgentCert` consumes it with an atomic `DELETE … RETURNING`, so
  a token works exactly once.
- Identity comes from the asset, not the CSR. warden derives the agent's SPIFFE id from
  the bound asset (`spiffe://jumpgate/agent/<asset_id>`) and ignores the CSR's own
  subject and SANs, so an enrolling agent cannot assert an identity it was not issued.
- Impersonation is confined to the verified token. The broker strips every
  client-supplied `Authorization` and `Impersonate-*` header and sets the identity
  solely from the token (`Impersonate-User` is the caller's email, one `Impersonate-Group`
  per token-carried group). A client cannot inject its own impersonation headers.
- The agent forwards as its own ServiceAccount, whose RBAC grants only the `impersonate`
  verb; the target cluster's RBAC then bounds what the impersonated groups may do.

Known gaps: agent certificates (24-hour TTL) are not auto-renewed — a long-lived agent
re-enrolls when its pod is recreated. The broker's tunnel advertisement is trusted from
a validly-signed agent cert without a separate asset-ownership check. The gateway's
serving certificate has no production DNS SAN yet, so `kubectl` currently trusts it via
an explicit CA. See [roadmap.md](roadmap.md#known-deferrals).

## Threat-model summary

| Threat | Mitigation | Status |
|---|---|---|
| Attacker maps infrastructure by probing | Existence-hiding: catalog returns only visible assets; invisible lookup → `CodeNotFound`, never `403` | Implemented |
| Stolen/leaked bearer token used indefinitely | Opaque DB-backed hashed tokens with expiry; instant server-side revocation (`Logout`) | Implemented |
| CSRF via browser cookie | `Sec-Fetch-Site: same-origin` required for cookie-authenticated requests; browsers set it automatically, cross-origin JS cannot forge it; missing header means the cookie is ignored | Implemented |
| Privilege creep / broad standing access | Requestable, approval-gated, JIT time-boxed grants (clamped to `MaxGrantTTL=8h`); approval gate travels with the role | Implemented |
| JIT grant used to self-escalate | Grants confer access but not governance: requester/approver predicates are standing-only, excluding active grants | Implemented |
| Over-broad management authority delegated | No-escalation subset rule: a caller can only bind or grant a role whose capabilities they already hold at that scope (`Covers`) | Implemented |
| Over-broad capability grant slips in unnoticed | Grammar validation at role creation; `**` is the explicit, auditable "whole scope"; `CapMatch` fails closed | Implemented |
| Access revoked but live session continues | Grant, binding, membership, or capability change re-evaluates authz and force-closes dependent live sessions (push plus pull, audited) | Implemented (SSH, Postgres, Kubernetes) |
| Compromised/departed user keeps acting | `deactivated_at` off-switch: rejected at Login and the auth interceptor, and filtered out of every authz closure; active grants revoked and sessions torn down | Implemented |
| Credential exposed on a compromised target | Agentless SSH/Postgres: no credential on targets, and the credential is short-lived (bounded by the grant) and held only for a live session | Implemented |
| Over-broad SSH host login (root-for-all) | SSH cert principals are capability-derived and host-scoped: only logins the user holds `ssh:login:<login>` for, bound to the asset; empty means refused; the CA refuses a principal-less cert | Implemented |
| Over-broad Postgres access | `db:login:<role>` gates each DB role; the broker mints a short-lived X.509 client cert (CN = the role) or returns the sealed password; the target is dialed over TLS with no plaintext downgrade | Implemented |
| Kubernetes admin becomes cluster-admin by accident | `k8s:group` is enumerated, not glob-matched, so `**` and `k8s:group:*` grant no groups; cluster-admin needs an explicit concrete grant and a matching cluster RBAC binding | Implemented |
| Kubernetes client forges its own identity | The broker strips client `Authorization`/`Impersonate-*` headers and sets identity solely from the verified token (email plus token-carried groups) | Implemented |
| Inbound reach into a customer cluster | The agent dials out over mesh mTLS and serves a reverse tunnel; jumpgate opens no inbound port and holds no long-lived cluster credential | Implemented |
| Rogue agent enrollment | Single-use, hashed, 30-minute enrollment token; the agent's SPIFFE id is derived from the bound asset, not the CSR | Implemented |
| Session activity not attributable | Sessions recorded by default (SSH asciicast, Postgres statement timeline, Kubernetes API audit), fail-closed, streamed to object storage with a rolling SHA-256; admin retrieval is presigned and audited | Implemented |
| Audit log tampered to hide activity | Hash-chained append-only log, independently verifiable; events enqueued in-tx via a transactional outbox (crash window closed; `credential.issued` post-fact) | Implemented |
| Secrets (CA keys, target creds) read at rest | Envelope encryption: per-secret AES-256-GCM DEK wrapped by a master KEK (`VAULT_MASTER_KEY`; KMS-pluggable); sealed bytes never leave the DB/API; fail-closed `Open` | Implemented |
| Master key lost/leaked | Losing `VAULT_MASTER_KEY` loses all sealed secrets (no recovery); KMS custody is the future seam — treat the key as a top-tier operational secret | Residual (documented; KMS deferred) |
| Worker impersonates another identity | mesh mTLS: warden derives the authoritative `worker_id` from the peer cert's SPIFFE SAN; the gateway pins each peer's SPIFFE id (chain-to-mesh-CA and URI-SAN match) | Implemented |

## Related

- [access-model.md](access-model.md) — who can do what, and the visibility tiers.
- [capabilities.md](capabilities.md) — the capability vocabulary and the
  decide/enforce split.
- [architecture.md](architecture.md) — the data plane, continuous revocation, audit.
- [data-model.md](data-model.md) — the tables behind all of the above.
- [decisions.md](decisions.md) — rationale for the auth, audit, and data-plane choices.
