# syntax=docker/dockerfile:1
#
# Independent "protected server" test-workload for the jumpgate demo/e2e.
#
# This is NOT part of the jumpgate control-plane deployment. It stands in for a
# real target host that an admin onboards via the CLI: an OpenSSH daemon that
# trusts jumpgate's SSH CA, so the ssh-proxy worker can authenticate with the
# CA-signed user certificates it mints. The ssh-proxy connects as
# deploy@ssh-target:22.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*

COPY test/env/testworkload/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
