# jumpgate demo walkthrough

A narrated, three-actor tour of the whole jumpgate flow, driven entirely through the
real `jumpgate` CLI against the containerized test environment. An **admin** onboards an
SSH asset and sets up a cross-approval request policy; two normal users, **alice** and
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

`kind-demo` creates the kind cluster, installs the chart, and writes the mesh CA to
`./jumpgate-mesh-ca.pem`. It prints the endpoints:

- warden user API: `http://localhost:8080`
- gateway: `localhost:8443`

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

Create a folder and onboard the sshd test workload as an SSH asset. Capture the asset id —
the admin has no standing access to a freshly onboarded asset, so it is not yet resolvable
by name (you will pass the id explicitly below):

```bash
jumpgate --context admin folders create demo

jumpgate --context admin assets onboard ssh demo-box \
  --folder demo \
  --target ssh-target.default.svc.cluster.local:22 \
  --login deploy -o json      # note the "id" -> ASSET_ID
```

Create the role the users will request. Its capability grants the `deploy` SSH login:

```bash
jumpgate --context admin roles create ssh-deploy \
  --capability ssh:login:deploy -o json   # note the "id" -> ROLE_ID
```

Create the two users with login passwords (a display name is required):

```bash
jumpgate --context admin users create alice@demo.test --name Alice --password alice-password-1234
jumpgate --context admin users create bob@demo.test   --name Bob   --password bob-password-1234
```

Create a request policy that makes `ssh-deploy` requestable at the asset scope, requiring
one approval, then add alice and bob as **both** requester and approver so either can
request and either can approve the other:

```bash
jumpgate --context admin policies create \
  --request-role ssh-deploy --asset <ASSET_ID> --min-approvals 1 -o json   # note the "id" -> POLICY_ID

jumpgate --context admin policies add-subject <POLICY_ID> --kind requester --user alice@demo.test
jumpgate --context admin policies add-subject <POLICY_ID> --kind approver  --user alice@demo.test
jumpgate --context admin policies add-subject <POLICY_ID> --kind requester --user bob@demo.test
jumpgate --context admin policies add-subject <POLICY_ID> --kind approver  --user bob@demo.test
```

## Act 1 — alice requests access

```bash
jumpgate login --context alice \
  --warden-addr http://localhost:8080 \
  --ca ./jumpgate-mesh-ca.pem \
  --email alice@demo.test --password alice-password-1234

# The role determines the real login; the "deploy@" prefix is cosmetic. A requester
# cannot yet resolve the asset/role by name, so pass the ids from Act 0.
jumpgate --context alice access request deploy@<ASSET_ID> \
  --role <ROLE_ID> --duration 1h --reason "need to check the demo box"   # note the "id" -> REQUEST_ID
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
jumpgate --context alice connect deploy@demo-box --ca ./jumpgate-mesh-ca.pem
```

You are now on the target over the tunnel. Run a few commands, then exit:

```bash
echo hello-from-jumpgate
hostname
whoami
exit
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
