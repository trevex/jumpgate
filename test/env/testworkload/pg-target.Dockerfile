FROM postgres:17
# Committed throwaway server cert+key: the init script installs these as the
# target's TLS identity so it presents a DETERMINISTIC leaf the operator pins at
# onboarding by exact SHA-256 fingerprint (see pg_test.go pgTargetLeafFP).
# Test-only material, never reused. Build context is test/env/testworkload.
COPY pg_server.crt /etc/pg/server.crt
COPY pg_server.key /etc/pg/server.key
COPY pg-target-init.sh /docker-entrypoint-initdb.d/10-tls-roles.sh
RUN chmod +x /docker-entrypoint-initdb.d/10-tls-roles.sh
