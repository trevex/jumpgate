#!/usr/bin/env bash
#
# Boot an OpenSSH daemon that trusts jumpgate's SSH CA and exposes a demo
# login account. Auth is via CA-signed user certificate only; there is no
# password on the demo account.
set -euo pipefail

CA_PUB=/etc/ssh/jumpgate_ca.pub

# Demo login account. No password is set: authentication is via SSH certificate
# only (the ssh-proxy presents a cert signed by warden's SSH CA).
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy

# Generate host keys if they are missing (idempotent).
ssh-keygen -A

# sshd refuses to run without its privilege-separation directory.
mkdir -p /run/sshd

# Drop-in config: trust the mounted CA public key, require pubkey/cert auth, and
# gate which certificate principals are accepted per user via a principals file.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/jumpgate.conf <<EOF
TrustedUserCAKeys /etc/ssh/jumpgate_ca.pub
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
EOF

# Per-user accepted-principals files live here. The file for a login lists the
# host-scoped principals sshd will accept from a CA-signed cert for that login.
# With no principal listed, sshd rejects every cert for that user (default-deny).
mkdir -p /etc/ssh/auth_principals

# Optimistic provisioning: when the asset path is known ahead of onboard (the
# admin picks deterministic folder/asset names), pass ASSET_PATH and the accepted
# principal is written at boot. Otherwise automation writes it post-onboard from
# the path returned by `assets ssh create` (see the e2e harness).
if [ -n "${ASSET_PATH:-}" ]; then
  echo "deploy@${ASSET_PATH}" > /etc/ssh/auth_principals/deploy
fi

if [ ! -f "${CA_PUB}" ]; then
  echo "WARNING: ${CA_PUB} is not present. The jumpgate SSH CA public key is" >&2
  echo "         normally mounted from the 'ssh-ca-pub' Secret. Starting sshd" >&2
  echo "         anyway for debuggability, but certificate auth WILL FAIL until" >&2
  echo "         the Secret is mounted." >&2
fi

# Foreground, log to stderr so container logs capture sshd output.
exec /usr/sbin/sshd -D -e
