# syntax=docker/dockerfile:1
#
# Independent public-key-auth "protected server" test-workload for the jumpgate
# demo/e2e.
#
# This is NOT part of the jumpgate control-plane deployment. It stands in for a
# real target host onboarded via the CLI whose asset credential is a stored
# private SSH key. An OpenSSH daemon exposes a demo account whose
# authorized_keys contains the matching throwaway test public key
# (demo_key.pub). The ssh-proxy worker connects as demo@ssh-target-key:22 using
# the stored private key. No CA trust here.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*

# Throwaway test-only public key installed into the demo account's
# authorized_keys by the entrypoint. Build context is test/env/testworkload.
COPY demo_key.pub /etc/ssh/demo_key.pub
# Committed throwaway host key: installed by the entrypoint as the sole ed25519
# host key so the target presents a deterministic identity pinned at onboarding
# by exact SHA-256 fingerprint. Test-only material, never reused.
COPY ssh_host_ed25519_key /etc/ssh/fixture_host_ed25519_key
COPY entrypoint-key.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
