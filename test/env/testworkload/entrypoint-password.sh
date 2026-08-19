#!/usr/bin/env bash
#
# Boot an OpenSSH daemon that exposes a demo login account authenticated by
# password. This stands in for a target host whose jumpgate asset credential is
# a stored username/password. There is no CA trust here.
#
# WARNING: the password below is a throwaway, hard-coded test credential for the
# kind demo/e2e ONLY. Do not reuse it anywhere real.
set -euo pipefail

DEMO_USER=demo
DEMO_PASSWORD=demo-password-123

# Demo login account with a known password.
id "${DEMO_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${DEMO_USER}"
echo "${DEMO_USER}:${DEMO_PASSWORD}" | chpasswd

# Generate host keys if they are missing (idempotent).
ssh-keygen -A

# sshd refuses to run without its privilege-separation directory.
mkdir -p /run/sshd

# Drop-in config: password auth only for the demo account.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/jumpgate.conf <<EOF
PasswordAuthentication yes
PermitEmptyPasswords no
EOF

# Foreground, log to stderr so container logs capture sshd output.
exec /usr/sbin/sshd -D -e
