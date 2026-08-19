#!/usr/bin/env bash
#
# Boot an OpenSSH daemon that exposes a demo login account authenticated by
# public key. This stands in for a target host whose jumpgate asset credential
# is a stored private SSH key; the matching public key (demo_key.pub, a
# throwaway test-only key) is installed into the demo account's authorized_keys.
# There is no CA trust and password auth is disabled.
set -euo pipefail

DEMO_USER=demo
DEMO_HOME=/home/${DEMO_USER}
DEMO_PUBKEY=/etc/ssh/demo_key.pub

# Demo login account. No password: authentication is via the installed pubkey.
id "${DEMO_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${DEMO_USER}"

# Install the throwaway test public key into authorized_keys with correct
# ownership and permissions.
install -d -m 0700 -o "${DEMO_USER}" -g "${DEMO_USER}" "${DEMO_HOME}/.ssh"
install -m 0600 -o "${DEMO_USER}" -g "${DEMO_USER}" \
  "${DEMO_PUBKEY}" "${DEMO_HOME}/.ssh/authorized_keys"

# Generate host keys if they are missing (idempotent).
ssh-keygen -A

# sshd refuses to run without its privilege-separation directory.
mkdir -p /run/sshd

# Drop-in config: public-key auth only.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/jumpgate.conf <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
EOF

# Foreground, log to stderr so container logs capture sshd output.
exec /usr/sbin/sshd -D -e
