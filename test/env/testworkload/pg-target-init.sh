#!/bin/bash
# First-boot init (runs from /docker-entrypoint-initdb.d/ while a temp server is up):
# self-sign a server cert, create the app role, enable TLS, and require TLS for app.
set -euo pipefail

# Self-signed server cert in PGDATA (owned by the postgres user running this script).
openssl req -new -x509 -days 3650 -nodes -text \
  -subj "/CN=pg-target" \
  -keyout "$PGDATA/server.key" -out "$PGDATA/server.crt"
chmod 600 "$PGDATA/server.key"

# App role (scram password; pg17 defaults password_encryption=scram-sha-256) + TLS config.
# mtlsuser: client-cert auth (pg-proxy mints a cert with CN=mtlsuser; postgres
# maps the cert CN to the pg role of the same name).
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname appdb <<-SQL
  CREATE ROLE app LOGIN PASSWORD 'app-e2e-pw';
  GRANT CONNECT ON DATABASE appdb TO app;
  CREATE ROLE mtlsuser LOGIN;
  GRANT CONNECT ON DATABASE appdb TO mtlsuser;
  ALTER SYSTEM SET ssl = on;
  ALTER SYSTEM SET ssl_cert_file = '$PGDATA/server.crt';
  ALTER SYSTEM SET ssl_key_file  = '$PGDATA/server.key';
  ALTER SYSTEM SET ssl_ca_file = '/etc/pg/jumpgate-x509-ca.crt';
SQL

# Require TLS for the app/mtlsuser roles. Prepend (not append): the entrypoint
# already added a permissive "host all all all scram-sha-256" catch-all to
# pg_hba.conf before running initdb.d scripts, and pg_hba is first-match-wins,
# so a line appended after it would be unreachable dead config for a
# plaintext attempt.
{
  echo "hostssl appdb app all scram-sha-256"
  echo "hostnossl appdb app all reject"
  echo "hostssl appdb mtlsuser all cert"
  echo "hostnossl appdb mtlsuser all reject"
  cat "$PGDATA/pg_hba.conf"
} > "$PGDATA/pg_hba.conf.tmp"
mv "$PGDATA/pg_hba.conf.tmp" "$PGDATA/pg_hba.conf"
