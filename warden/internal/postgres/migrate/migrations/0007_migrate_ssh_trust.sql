-- +goose Up
-- +goose StatementBegin

-- Enable the SSH verification vertical slice for pre-existing assets: queue one
-- onboarding probe per existing SSH asset at its current endpoint revision, so the
-- data plane observes and verifies each target under the new fail-closed sessions.
--
-- Converting a pinned host_public_key into an approved migration-source trust anchor
-- is done by the one-shot Go helper BackfillSSHTrustAnchors, invoked once at startup
-- after migrations. SQL cannot safely canonicalize or SHA-256 fingerprint OpenSSH
-- material — a well-formed base64 blob that is not a real key would be fingerprinted
-- and trusted — so key parsing stays in Go where an invalid key is never trusted.
--
-- Idempotent: the WHERE NOT EXISTS guard mirrors the target_probe_jobs partial unique
-- index (one active onboarding/endpoint_changed job per asset+revision).
INSERT INTO target_probe_jobs (asset_id, endpoint_revision, protocol, state, reason)
SELECT a.id, a.endpoint_revision, 'ssh', 'queued', 'onboarding'
FROM assets a
WHERE a.kind = 'ssh'
  AND NOT EXISTS (
      SELECT 1
      FROM target_probe_jobs j
      WHERE j.asset_id = a.id
        AND j.endpoint_revision = a.endpoint_revision
        AND j.reason IN ('onboarding', 'endpoint_changed')
        AND j.state IN ('queued', 'leased')
  );

-- +goose StatementEnd

-- +goose Down
-- Data-only migration; queued onboarding probes and migration anchors are left in
-- place on down (they are harmless once verification is disabled).
