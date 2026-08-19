#!/usr/bin/env bash
#
# End-to-end smoke test for the jumpgate kind environment.
#
# Assumes `make kind-up` has already run: the cluster is up, cert-manager and the
# jumpgate chart are installed, all pods are ready, and the ssh test workload is
# deployed. It drives the real `jumpgate` CLI against the running stack — warden's
# user API on http://localhost:8080 and the gateway on localhost:8443 — to prove
# the whole path works: login -> onboard an SSH asset -> grant a role -> connect
# through the gateway and run a command on the target -> confirm a recording lands.
#
# It exits 0 only if every step passes. Progress and PASS/FAIL markers go to
# stderr; the script leaves no state on the host's real CLI config (it uses a
# throwaway XDG_CONFIG_HOME).
#
# Environment overrides:
#   WARDEN_ADDR       warden user API base URL   (default http://localhost:8080)
#   ADMIN_EMAIL       bootstrap admin email      (default admin@demo.test)
#   ADMIN_PASSWORD    bootstrap admin password   (default admin-password-1234)
#   JUMPGATE_BIN      path to a prebuilt CLI     (default: built from ./cli)
#   MESH_CA           mesh CA PEM path           (default ./jumpgate-mesh-ca.pem)

set -euo pipefail

WARDEN_ADDR="${WARDEN_ADDR:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@demo.test}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin-password-1234}"

# Resolve the repo root from this script's location (deploy/kind/smoke.sh) so the
# script works regardless of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MESH_CA="${MESH_CA:-${REPO_ROOT}/jumpgate-mesh-ca.pem}"

# Marker names used across the whole scenario.
FOLDER_NAME="demo"
ASSET_NAME="demo-box"
ROLE_NAME="ssh-deploy"
LOGIN="deploy"
SSH_TARGET="ssh-target.default.svc.cluster.local:22"
SMOKE_TOKEN="JUMPGATE_SMOKE_OK"

log()  { printf '>>> %s\n' "$*" >&2; }
pass() { printf 'PASS: %s\n' "$*" >&2; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# Give the CLI a private, writable config dir so `login` does not clobber a real
# ~/.config/jumpgate on the host. Cleaned up on exit.
XDG_CONFIG_HOME="$(mktemp -d)"
export XDG_CONFIG_HOME
cleanup() { rm -rf "${XDG_CONFIG_HOME}"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. Locate/build the CLI.
# ---------------------------------------------------------------------------
if [[ -n "${JUMPGATE_BIN:-}" ]]; then
  JG="${JUMPGATE_BIN}"
else
  JG="${REPO_ROOT}/jumpgate-cli"
  log "building the jumpgate CLI -> ${JG}"
  if command -v nix >/dev/null 2>&1; then
    nix develop "${REPO_ROOT}" --command bash -c \
      "cd '${REPO_ROOT}/cli' && go build -o '${JG}' ." \
      || fail "building the CLI"
  else
    ( cd "${REPO_ROOT}/cli" && go build -o "${JG}" . ) || fail "building the CLI"
  fi
fi
[[ -x "${JG}" ]] || fail "CLI binary not executable: ${JG}"
pass "CLI available: ${JG}"

# json_id extracts the first top-level "id" field from protojson output. The CLI
# renders create responses via protojson (camelCase keys, multiline with `-o
# json`), so the asset/role/folder id prints as `  "id": "<uuid>"`. python3 may be
# absent in the harness, so parse with grep/sed only.
json_id() {
  grep -m1 -oE '"id":[[:space:]]*"[^"]+"' | sed -E 's/.*"id":[[:space:]]*"([^"]+)".*/\1/'
}

# ---------------------------------------------------------------------------
# 1. Export the gateway's mesh CA so the CLI can verify the gateway's TLS when it
#    dials the data-plane tunnel. `make kind-demo` writes this too, but the plain
#    `kind-up` path may not have, so we (re)export it here.
# ---------------------------------------------------------------------------
log "exporting the gateway mesh CA -> ${MESH_CA}"
kubectl get secret jumpgate-gateway-ext \
  -o go-template='{{index .data "ca.crt" | base64decode}}' > "${MESH_CA}" \
  || fail "exporting the mesh CA"
[[ -s "${MESH_CA}" ]] || fail "mesh CA file is empty: ${MESH_CA}"
pass "mesh CA exported"

# ---------------------------------------------------------------------------
# 2. Log in as the bootstrap admin. Storing --ca in the context makes it the CA
#    the later `connect` uses for the gateway tunnel dial.
# ---------------------------------------------------------------------------
log "logging in as ${ADMIN_EMAIL}"
"${JG}" login \
  --context admin \
  --warden-addr "${WARDEN_ADDR}" \
  --ca "${MESH_CA}" \
  --email "${ADMIN_EMAIL}" \
  --password "${ADMIN_PASSWORD}" >&2 \
  || fail "login"
pass "logged in (context: admin)"

# ---------------------------------------------------------------------------
# 3. Create the demo folder.
# ---------------------------------------------------------------------------
log "creating folder ${FOLDER_NAME}"
FOLDER_ID="$("${JG}" folders create "${FOLDER_NAME}" -o json | json_id)" \
  || fail "creating folder"
[[ -n "${FOLDER_ID}" ]] || fail "no folder id returned"
pass "folder ${FOLDER_NAME} (${FOLDER_ID})"

# ---------------------------------------------------------------------------
# 4. Onboard the SSH asset. The target is the in-cluster sshd Service DNS name;
#    --login is the account the CA-issued cert is allowed to log in as.
# ---------------------------------------------------------------------------
log "onboarding SSH asset ${ASSET_NAME} -> ${SSH_TARGET}"
ASSET_ID="$("${JG}" assets onboard ssh "${ASSET_NAME}" \
  --folder "${FOLDER_NAME}" \
  --target "${SSH_TARGET}" \
  --login "${LOGIN}" \
  -o json | json_id)" \
  || fail "onboarding asset"
[[ -n "${ASSET_ID}" ]] || fail "no asset id returned"
pass "asset ${ASSET_NAME} (${ASSET_ID})"

# ---------------------------------------------------------------------------
# 5. Create a role that carries the ssh:login:<login> capability.
# ---------------------------------------------------------------------------
log "creating role ${ROLE_NAME} (ssh:login:${LOGIN})"
ROLE_ID="$("${JG}" roles create "${ROLE_NAME}" \
  --capability "ssh:login:${LOGIN}" \
  -o json | json_id)" \
  || fail "creating role"
[[ -n "${ROLE_ID}" ]] || fail "no role id returned"
pass "role ${ROLE_NAME} (${ROLE_ID})"

# ---------------------------------------------------------------------------
# 6. Bind the role to the admin (the logged-in subject) scoped to the asset. The
#    CLI resolves the user by email, the role by name, and the asset by name.
# ---------------------------------------------------------------------------
log "binding ${ROLE_NAME} -> ${ADMIN_EMAIL} @ ${ASSET_NAME}"
"${JG}" bindings create \
  --role "${ROLE_NAME}" \
  --user "${ADMIN_EMAIL}" \
  --asset "${ASSET_NAME}" >&2 \
  || fail "creating binding"
pass "role bound to admin at asset scope"

# ---------------------------------------------------------------------------
# 7. Connect through the gateway and run a command. `connect` opens a shell over
#    the tunnel (no command-arg form); when stdin is not a TTY it runs the piped
#    input as a non-interactive shell, so we feed it an echo + exit and grep the
#    output for the marker. --ca points at the exported mesh CA so the gateway TLS
#    verifies. A timeout guards against a hung tunnel.
# ---------------------------------------------------------------------------
log "connecting to ${LOGIN}@${ASSET_NAME} and running a command"
CONNECT_OUT="$(printf 'echo %s; exit\n' "${SMOKE_TOKEN}" \
  | timeout 30 "${JG}" connect "${LOGIN}@${ASSET_NAME}" --ca "${MESH_CA}" 2>&1)" \
  || fail "connect exited non-zero; output: ${CONNECT_OUT}"
if grep -q "${SMOKE_TOKEN}" <<<"${CONNECT_OUT}"; then
  pass "connect ran a command on the target (saw ${SMOKE_TOKEN})"
else
  fail "connect output did not contain ${SMOKE_TOKEN}; output: ${CONNECT_OUT}"
fi

# ---------------------------------------------------------------------------
# 8. Poll for a completed recording of the session we just ran. The worker
#    streams the recording to object storage and reports completion to warden
#    asynchronously, so poll for up to ~30s.
# ---------------------------------------------------------------------------
log "waiting for a completed session recording (up to 30s)"
recording_ready=false
for _ in $(seq 1 30); do
  REC_JSON="$("${JG}" recordings list -o json 2>/dev/null || true)"
  # protojson emits the recording status as `"status": "completed"`.
  if grep -q '"status":[[:space:]]*"completed"' <<<"${REC_JSON}"; then
    recording_ready=true
    break
  fi
  sleep 1
done
if [[ "${recording_ready}" == true ]]; then
  pass "a completed recording is present"
else
  fail "no completed recording appeared within 30s"
fi

log "ALL STEPS PASSED"
exit 0
