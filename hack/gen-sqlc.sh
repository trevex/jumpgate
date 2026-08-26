#!/usr/bin/env bash
# Regenerate the sqlc database-access code against a throwaway PostgreSQL.
#
# sqlc runs in database-backed analysis mode (see sqlc.yaml: database.uri) so it
# can resolve the RETURNS TABLE columns of the authz_* SQL set-returning
# functions, which the built-in query analyzer cannot infer. This script spins an
# ephemeral PostgreSQL on a Unix socket in a short temp dir (keeping the socket
# path well under the 107-byte sun_path limit), applies the schema with goose,
# points sqlc at it via SQLC_PG_URI, generates, and always tears the server down.
#
# Requires initdb, pg_ctl, goose and sqlc on PATH (provided by the Nix devshell).
set -euo pipefail

MIGRATIONS_DIR="warden/internal/postgres/migrate/migrations"

PGTMP="$(mktemp -d "${TMPDIR:-/tmp}/jgsqlc.XXXXXX")"
cleanup() {
  pg_ctl -D "$PGTMP/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$PGTMP"
}
trap cleanup EXIT INT TERM

initdb -D "$PGTMP/data" -U postgres --no-sync >/dev/null
# Socket-only server (no TCP) so parallel runs never contend for a port.
pg_ctl -D "$PGTMP/data" -o "-k $PGTMP -c listen_addresses=" -w -l "$PGTMP/log" start >/dev/null

export SQLC_PG_URI="postgresql://postgres@/postgres?host=${PGTMP}&sslmode=disable"
goose -dir "$MIGRATIONS_DIR" postgres "$SQLC_PG_URI" up >/dev/null
sqlc generate
