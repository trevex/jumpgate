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

# Drop-in config: trust the mounted CA public key and require pubkey/cert auth.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/jumpgate.conf <<EOF
TrustedUserCAKeys /etc/ssh/jumpgate_ca.pub
PubkeyAuthentication yes
PasswordAuthentication no
EOF

if [ ! -f "${CA_PUB}" ]; then
  echo "WARNING: ${CA_PUB} is not present. The jumpgate SSH CA public key is" >&2
  echo "         normally mounted from the 'ssh-ca-pub' Secret. Starting sshd" >&2
  echo "         anyway for debuggability, but certificate auth WILL FAIL until" >&2
  echo "         the Secret is mounted." >&2
fi

# Foreground, log to stderr so container logs capture sshd output.
exec /usr/sbin/sshd -D -e
