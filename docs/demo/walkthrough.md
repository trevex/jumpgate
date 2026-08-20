# jumpgate demo walkthrough

A narrated, three-actor tour of the whole jumpgate flow, driven entirely through the
real `jumpgate` CLI against the containerized test environment. An **admin** onboards three
SSH assets (cert, password, key) and sets up a cross-approval request policy; two normal users, **alice** and
**bob**, can each request access *and* approve the other; alice requests, bob approves,
alice connects and runs a command, and the admin (as auditor) downloads the recording and
confirms it captured the session.

> The automated twin of this walkthrough is the Go e2e suite in `test/e2e`
> (`make kind-e2e`). It runs the same command sequence with assertions — keep the two in
> lockstep when either changes.

## Prerequisites

Bring up the test environment and export the gateway mesh CA (used to verify the tunnel
TLS when the CLI connects):

```bash
make kind-demo
```

`kind-demo` creates the kind cluster, installs the chart, writes the mesh CA to
`./jumpgate-mesh-ca.pem`, and builds the CLI to `./jumpgate`. It prints the endpoints:

- warden user API: `http://localhost:8080`
- gateway: `localhost:8443`

The freshly built `./jumpgate` is not on your PATH. Alias it so the `jumpgate …` commands
below work as written (skip this if `jumpgate` is already installed on your PATH):

```bash
alias jumpgate=./jumpgate
```

Recording downloads are served by the in-cluster object store exposed at
`localhost:30900`; warden signs its download URLs for that host, so nothing extra is
needed to fetch them.

All commands below use kubectl-style named contexts (`--context admin|alice|bob`) stored
in one CLI config, so you can switch actors from a single terminal.

## Act 0 — the admin sets the stage

Log in as the bootstrap admin (storing the mesh CA in the context so `connect` uses it
later):

```bash
jumpgate login --context admin \
  --warden-addr http://localhost:8080 \
  --ca ./jumpgate-mesh-ca.pem \
  --email admin@demo.test --password admin-password-1234
```

Create a folder and onboard three sshd test workloads as SSH assets (cert, password, key):

```bash
jumpgate --context admin folders create demo

jumpgate --context admin assets ssh create demo-box \
  --folder demo \
  --target ssh-target.default.svc.cluster.local:22 \
  --login deploy -o json      # "path" = demo-box.demo
```

A CA target only accepts a certificate whose principal it has been told to trust. Provision the
target's `AuthorizedPrincipalsFile` with the host-scoped principal `<login>@<path>` — the asset
path is deterministic (`demo-box.demo`), so a real operator can even do this ahead of onboarding:

```bash
kubectl exec deploy/ssh-target -- sh -c \
  'mkdir -p /etc/ssh/auth_principals && echo "deploy@demo-box.demo" > /etc/ssh/auth_principals/deploy'
```

`--login deploy` adds a `ca` login (a short-lived signed cert); this ca box drives the
request/approve flow below. To show the other two SSH auth kinds, onboard the two dedicated
workloads as their own assets — each with a `demo` login. Admin commands can address any asset
by its DNS path once it exists in the catalog:

```bash
# password workload:
jumpgate --context admin assets ssh create password-box \
  --folder demo \
  --target ssh-target-password.default.svc.cluster.local:22
printf 'demo-password-123\n' | jumpgate --context admin assets ssh login set password-box.demo \
  --login demo --kind password --password-stdin

# key workload:
jumpgate --context admin assets ssh create key-box \
  --folder demo \
  --target ssh-target-key.default.svc.cluster.local:22
jumpgate --context admin assets ssh login set key-box.demo \
  --login demo --kind key --key-file test/env/testworkload/demo_key
```

Create the role the users will request. Its capability grants the `deploy` SSH login. Both
roles are scoped to the `demo` folder with `--folder demo`, so they can only be bound or made
requestable within that subtree and are addressable as `ssh-deploy.demo` / `ssh-demo.demo`:

```bash
jumpgate --context admin roles create ssh-deploy \
  --folder demo \
  --capability ssh:login:deploy -o json

jumpgate --context admin roles create ssh-demo \
  --folder demo \
  --capability ssh:login:demo -o json
```

Create the two users with login passwords (a display name is required):

```bash
jumpgate --context admin users create alice@demo.test --name Alice --password alice-password-1234
jumpgate --context admin users create bob@demo.test   --name Bob   --password bob-password-1234
```

Put both users in an **sre** group and assign permissions to the group rather than to the
individuals — access flows through membership. (Group names are globally unique, so a group is
always referenced by name; groups can also nest, in which case membership is walked transitively.)

```bash
jumpgate --context admin groups create sre
jumpgate --context admin groups add-member sre alice@demo.test
jumpgate --context admin groups add-member sre bob@demo.test
```

Grant the **sre** group **standing** access to the password and key boxes (no request needed — a
contrast with the ca box's just-in-time flow). Bind `ssh-demo` to the group on each box. Because the
role is folder-scoped, it is addressed by its namespaced DNS name `ssh-demo.demo` (a bare `ssh-demo`
would resolve as a *global* role); the group resolves by name and the assets by their DNS path:

```bash
jumpgate --context admin bindings create --role ssh-demo.demo --group sre --asset password-box.demo
jumpgate --context admin bindings create --role ssh-demo.demo --group sre --asset key-box.demo
```

Create a request policy that makes `ssh-deploy` requestable at the asset scope, requiring
one approval, then make the **sre** group **both** requester and approver — any member can request
and any *other* member can approve (alice and bob approve each other via the group). The policy
is given a name so it can be addressed as `approve-deploy@demo-box.demo`:

```bash
jumpgate --context admin policies create \
  --name approve-deploy --request-role ssh-deploy --asset demo-box.demo --min-approvals 1

jumpgate --context admin policies add-subject approve-deploy@demo-box.demo --kind requester --group sre
jumpgate --context admin policies add-subject approve-deploy@demo-box.demo --kind approver  --group sre
```

## Act 1 — alice requests access

```bash
jumpgate login --context alice \
  --warden-addr http://localhost:8080 \
  --ca ./jumpgate-mesh-ca.pem \
  --email alice@demo.test --password alice-password-1234

# alice can see what she may request (by name), then request by path + name — no ids.
# The role determines the real login; the "deploy@" prefix is cosmetic.
jumpgate --context alice assets get demo-box.demo        # shows ssh-deploy under REQUESTABLE ROLES
jumpgate --context alice access request deploy@demo-box.demo \
  --role ssh-deploy --duration 1h --reason "need to check the demo box"   # note the "id" -> REQUEST_ID
```

## Act 2 — bob approves

```bash
jumpgate login --context bob \
  --warden-addr http://localhost:8080 \
  --ca ./jumpgate-mesh-ca.pem \
  --email bob@demo.test --password bob-password-1234

jumpgate --context bob access list --pending-approvals   # alice's request is listed
jumpgate --context bob access approve <REQUEST_ID>
```

## Act 3 — alice connects and does things

The approval created a time-boxed grant. With the grant, alice can now resolve the asset
by name and connect through the gateway:

```bash
jumpgate --context alice access grants                    # the active grant is listed
jumpgate --context alice connect deploy@demo-box.demo --ca ./jumpgate-mesh-ca.pem
```

You are now on the target over the tunnel. Run a few commands, then exit:

```bash
echo hello-from-jumpgate
hostname
whoami
exit
```

The password and key boxes need no request — alice already has standing access. She connects
the same way (the worker injects the stored password or key at the target hop):

```bash
jumpgate --context alice connect demo@password-box.demo --ca ./jumpgate-mesh-ca.pem
jumpgate --context alice connect demo@key-box.demo --ca ./jumpgate-mesh-ca.pem
```

## Act 4 — the auditor verifies the recording

The session was recorded. Recordings are admin-only audit artifacts, so bob (a peer
approver) cannot read them — the admin acts as auditor:

```bash
jumpgate --context admin recordings list                  # find the completed recording's SESSION id
jumpgate --context admin recordings download <SESSION_ID> --file recording.cast
asciinema play recording.cast                             # replay alice's session
```

The replay shows exactly what alice typed — closing the loop from request, through
approval and connection, to the audit trail.
