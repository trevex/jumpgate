# syntax=docker/dockerfile:1
#
# Independent password-auth "protected server" test-workload for the jumpgate
# demo/e2e.
#
# This is NOT part of the jumpgate control-plane deployment. It stands in for a
# real target host onboarded via the CLI whose asset credential is a stored
# username/password. An OpenSSH daemon exposes a demo account authenticated by
# password; there is no CA trust here. The ssh-proxy worker connects as
# demo@ssh-target-password:22 using the stored password.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint-password.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
