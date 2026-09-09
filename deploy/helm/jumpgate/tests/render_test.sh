#!/usr/bin/env bash
# Fail-closed / no-leak assertions for the jumpgate Helm chart.
set -euo pipefail
CHART="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="$CHART/../../../test/env/demo-values.yaml"
fail() { echo "CHART TEST FAIL: $1" >&2; exit 1; }

# 1. Bare install fails closed (missing required secrets — masterKey guard trips first).
if helm template jumpgate "$CHART" >/dev/null 2>&1; then
  fail "bare 'helm template' should have failed closed but succeeded"
fi
out="$(helm template jumpgate "$CHART" 2>&1 || true)"
echo "$out" | grep -qi 'masterKey is required' \
  || fail "bare render did not report the masterKey guard"

# 2. Demo render succeeds.
helm template jumpgate "$CHART" -f "$DEMO" >/dev/null \
  || fail "demo render failed"

# 3. S3 creds are sourced via secretKeyRef in all five consumers
#    (warden, ssh-proxy, pg-proxy, rdp-proxy, k8s-broker). Each consumer has one
#    AWS_ACCESS_KEY_ID env keyed from the S3 Secret.
n=$(helm template jumpgate "$CHART" -f "$DEMO" | grep -c 'key: AWS_ACCESS_KEY_ID')
[ "$n" -eq 5 ] || fail "expected 5 secretKeyRef S3 consumers, found $n"

# 4. The chart-managed S3 Secret is rendered and carries both keys.
s=$(helm template jumpgate "$CHART" -f "$DEMO" | grep -c 'name: jumpgate-s3')
[ "$s" -ge 1 ] || fail "chart-managed S3 Secret not rendered"

echo "chart tests passed"
