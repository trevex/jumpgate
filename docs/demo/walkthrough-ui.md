# jumpgate demo walkthrough — the console (UI)

The same three-actor tour as [`walkthrough.md`](./walkthrough.md), driven entirely through the
**browser console** instead of the CLI. An **admin** onboards three SSH assets (cert, password,
key) and makes one requestable through a cross-approval policy; two users, **alice** and **bob**,
each request access *and* approve the other; alice requests, bob approves, alice connects in an
in-browser terminal and runs a command; the admin plays back the recording. A final chapter
delegates a sub-folder to **dana** and shows the boundaries — all in the UI.

> **Sessions.** The console authenticates with a session **cookie**, so each actor needs an
> isolated browser session. Use one **private/incognito window per actor** (or separate browser
> profiles). Keep the admin, alice, bob, and dana windows side by side — that is the whole point:
> separation of duties is real, and you switch *windows*, not `--context` flags.

## Prerequisites

Bring up the environment (this builds the images, installs the chart, and serves the console):

```bash
make kind-demo      # or: make kind-up
```

Open the console at **http://localhost:8080**. Recording playback and the in-browser terminal work
out of the box (the gateway's terminal WSS uses the mesh CA; your browser will prompt once to accept
it the first time you open a terminal).

**One step has no UI — and shouldn't.** A CA SSH target only trusts a certificate whose *principal*
it has been told about. Provisioning the target's `AuthorizedPrincipalsFile` is a **target-host**
operation, not a jumpgate action, so it stays out-of-band (the host owner does it, or `kubectl` in
this demo). Because the asset path is deterministic (`demo-box.demo`), you can even do it before
onboarding:

```bash
kubectl exec deploy/ssh-target -- sh -c \
  'mkdir -p /etc/ssh/auth_principals && echo "deploy@demo-box.demo" > /etc/ssh/auth_principals/deploy'
```

Everything else below is done in the browser.

---

## Act 0 — the admin sets the stage  ·  *admin window*

**Sign in.** Open http://localhost:8080 → you land on **Sign in**. Enter `admin@demo.test` /
`admin-password-1234`. You arrive on the **Overview** dashboard.

**Create the `demo` folder.** Go to **Catalog** (sidebar). In the tree pane header click **+**
(*Create…*) → **New folder** → name it `demo` → **Create folder**. It appears in the tree.

**Onboard the three SSH assets.** Assets live in a folder, and the **+** is context-sensitive:
select the `demo` folder in the tree first, then use **+** (now scoped to `demo`).

1. **demo-box (CA / signed cert).** Select `demo` → **+** → **New asset**. In the wizard:
   - **Name** `demo-box`
   - **Target address** `ssh-target.default.svc.cluster.local:22`
   - Under **Logins**, the pre-filled row is a **CA (signed cert)** login — set its name to `deploy`.
   - **Create asset**. (This is the box the request/approve flow uses. Its `deploy@demo-box.demo`
     principal was provisioned in Prerequisites.)
2. **password-box (password).** Select `demo` → **+** → **New asset**. Name `password-box`, target
   `ssh-target-password.default.svc.cluster.local:22`. On the login row pick kind **Password**, name
   it `demo`, and type the password `demo-password-123` in the secret field. **Create asset**.
3. **key-box (private key).** Select `demo` → **+** → **New asset**. Name `key-box`, target
   `ssh-target-key.default.svc.cluster.local:22`. Login kind **Private key**, name `demo`, and
   **paste the PEM** (`test/env/testworkload/demo_key`) into the multi-line key box. **Create asset**.

**Create the two roles** (folder-scoped to `demo`). Select `demo` → **+** → **New role**. The folder
context is pre-filled, so the role is homed in `demo`:
- `ssh-deploy` — add capability `ssh:login:deploy` (type it in the capability field and add the chip).
- `ssh-demo` — add capability `ssh:login:demo`.

(You can also create roles from **Access control ▸ Roles ▸ New role**; from the catalog they pre-home
in the selected folder.)

**Create the two users.** Go to **Directory ▸ Users ▸ New user**:
- `alice@demo.test` — name **Alice**, a password.
- `bob@demo.test` — name **Bob**, a password.

**Create the `sre` group and add both users.** **Directory ▸ Groups ▸ New group** → name `sre`, leave
the folder home empty (a **global** group). Open the `sre` row → in the group detail **Add member** →
pick **Alice**, then **Add member** → **Bob**. (Access flows through membership; you'll grant the
*group*, never the individuals.)

**Grant standing access to the password + key boxes** (no request needed — the contrast with the CA
box's just-in-time flow). This binds `ssh-demo` to the `sre` group on each box:
- Select **password-box** in the tree → in the asset detail, **Bindings ▸ Bind a role**. Pick role
  **ssh-demo** (folder-scoped roles now appear in the picker), subject **group → sre**. The scope is
  pinned to this asset. **Create binding.**
- Repeat on **key-box**.

*(Equivalently, from **ssh-demo**'s role detail use **Bind this role** and choose the asset + group.)*

**Make demo-box requestable — by the `sre` group.** Select **demo-box** → asset detail → **Make
requestable**. In the New request policy dialog:
- **Requestable role** → **ssh-deploy**
- **Required approvals** → **1**
- **Requesters** → **Add requester** → group **sre**
- **Approvers** → **Add approver** → group **sre**
- **Create policy.**

That's the cross-approval setup in one dialog: any `sre` member can request, any *other* `sre` member
can approve. It now shows under demo-box's **Requestable via** section.

---

## Act 1 — alice requests access  ·  *alice window (incognito)*

Sign in as `alice@demo.test`. Go to **Catalog**, expand **demo**, select **demo-box**. The detail
pane shows **Requestable roles → ssh-deploy**. Click **Request access**, choose role **ssh-deploy**,
a duration (e.g. **1h**), a reason (“need to check the demo box”), and **Submit request**.

In **My Access ▸ Requests** the request shows **Pending**. Hover the ⓘ next to it: *you can't approve
your own request — a different eligible approver must act.*

## Act 2 — bob approves  ·  *bob window (incognito)*

Sign in as `bob@demo.test`. Go to **Approvals** (a badge shows the count). Alice's request is listed,
resolved to real names (Alice / demo-box.demo). Expand **decision context** to see the target host and
the capabilities the role grants, then click **Approve**. The row clears.

## Act 3 — alice connects  ·  *alice window*

Back in the alice window, **My Access ▸ Grants** now shows an **active** grant for `demo-box.demo`
with a countdown. Click **Open terminal (deploy)** → a full-screen in-browser terminal opens and
connects through the gateway. Run a few commands, then exit:

```
echo hello-from-jumpgate
hostname
whoami
exit
```

The **password** and **key** boxes need no request — alice already has standing access via `sre`.
In **Catalog**, select **password-box** (or **key-box**) → **Open terminal (demo)** and you're on the
target (the worker injects the stored password/key at the target hop).

## Act 4 — the auditor plays the recording  ·  *admin window*

Recordings are admin-only audit artifacts (bob, a peer approver, has no **Recordings** nav). In the
admin window go to **Recordings**, pick alice's session (asset + actor + time are shown), and it plays
inline in the asciinema player — exactly what alice typed. You can also reach an asset's recordings
from **Catalog ▸ demo-box ▸ Recordings**.

That closes the loop: request → approval → connection → audit, entirely in the browser.

---

## Chapter: delegated folder administration  ·  *admin, then dana*

Management is **capability-gated** and authority **cascades down** the folder tree: a capability held
at folder *F* applies to *F*, its sub-folders, and their assets — never upward. The bootstrap admin
simply holds `**` globally. Here the admin hands a `team` sub-folder to **dana**, who becomes a folder
admin for that subtree *and only that subtree*.

**As admin:**

1. **Carve out `team` under `demo`.** Select **demo** in the Catalog tree → **+** → **New folder** →
   `team`. (The child path is `team.demo`.)
2. **Define a bounded folder-admin role.** **Access control ▸ Roles ▸ New role** (leave it **global** —
   the *binding* is what scopes it). Name it `folder-admin` and add capabilities:
   `catalog:asset:create`, `catalog:asset:read`, `catalog:asset:update`, `access:role:create`,
   `access:binding:create`, `access:policy:create`, `identity:group:create`, `identity:group:read`,
   `identity:group:add-member`, `ssh:login:*`.
3. **Create dana.** **Directory ▸ Users ▸ New user** → `dana@demo.test`, name **Dana**, a password.
4. **Bind folder-admin to dana at `team`.** Select the **team** folder → **Bindings ▸ Bind a role** →
   role **folder-admin**, subject **user → Dana**. Scope is pinned to `team`. Because the admin holds
   `**` at `team`, the no-escalation rule is satisfied and the bind is allowed.

**As dana** (a fourth incognito window, `dana@demo.test`):

- She lands on Overview; **Catalog** shows only what she governs — the **team** folder is visible
  (her `catalog:asset:read` cascades to it), and she can browse into it.
- Select **team** → **+** offers **New folder / asset / role / group** (her caps at `team`). Onboard
  **team-box** (`ssh-target.default.svc.cluster.local:22`, CA login `deploy`), mint a team-scoped role
  **deployer** (`ssh:login:deploy`), and bind it to herself on **team-box** — all within `team`.

**Her authority stops at the delegated edge.** The UI shows the boundary two ways — *absent
affordances* and *server-enforced errors*:

- **Up the tree (denied):** navigate to the **demo** folder. There is **no +** create menu and no
  bind action — she holds nothing at `demo`. Authority cascades *down*, never up.
- **Escalation (denied):** if she opens **Bind a role** on `team` and picks the all-powerful
  `folder-admin` role, the server rejects it — a red toast: *permission denied*. She can only hand out
  what she herself holds at that scope (`folder-admin` carries caps she lacks).
- **Global operation (denied):** **Directory ▸ Users** shows **no New user** button — creating a user
  needs `identity:user:create` globally, which she doesn't have.

### Delegated group administration

Groups are *folder-homed*, and the folder is **governance-only** — it decides who may administer the
group, not who belongs to it. dana holds `identity:group:{create,read,add-member}` at `team`:

- **Allowed:** select **team** → **+** → **New group** → `sre` (homed in `team`; the folder context is
  pre-filled). Open it → **Add member** → **Dana**. (Membership is orthogonal to the home folder.)
- **Denied (up the tree):** she has no create affordance on the **demo** folder.
- **Denied (global):** **Directory ▸ Groups** shows no **New group** button — a global group needs
  `identity:group:create` at the global scope, which she holds nowhere.

The model in one breath: **capabilities** name what you can do; **folder-scoped bindings** say where;
authority **cascades** down the subtree; the **no-escalation** rule stops a delegate handing out more
than they hold; the admin is just the holder of `**`. In the console this surfaces as *what you can
see and click* — the affordances that appear are exactly the ones you're allowed to use.

---

> **Keeping the two guides honest.** This is the UI twin of the CLI [`walkthrough.md`](./walkthrough.md)
> and the automated `test/e2e` suite. When a flow changes, update all three. The one step with no UI —
> the target's `AuthorizedPrincipalsFile` — is a host-side operation by design, not a jumpgate action.
