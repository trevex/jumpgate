-- name: CreateProbeJob :one
INSERT INTO target_probe_jobs (
    previous_job_id,
    asset_id,
    endpoint_revision,
    protocol,
    state,
    reason,
    requested_by,
    max_attempts,
    next_attempt_at
)
VALUES (
    sqlc.narg('previous_job_id')::uuid,
    sqlc.arg('asset_id'),
    sqlc.arg('endpoint_revision'),
    sqlc.arg('protocol'),
    'queued',
    sqlc.arg('reason'),
    sqlc.narg('requested_by')::uuid,
    sqlc.arg('max_attempts'),
    sqlc.arg('next_attempt_at')
)
RETURNING *;

-- name: ClaimProbeJob :one
WITH candidate AS MATERIALIZED (
    SELECT j.id
    FROM target_probe_jobs j
    JOIN assets a
      ON a.id = j.asset_id
     AND a.endpoint_revision = j.endpoint_revision
     AND a.kind = j.protocol
    WHERE j.state = 'queued'
      AND j.next_attempt_at <= now()
      AND j.attempt_count < j.max_attempts
    ORDER BY j.next_attempt_at, j.created_at, j.id
    FOR UPDATE OF j SKIP LOCKED
    LIMIT 1
), leased AS (
    UPDATE target_probe_jobs j
    SET state = 'leased',
        attempt_count = j.attempt_count + 1,
        lease_worker_id = sqlc.arg('worker_id'),
        lease_token_hash = sqlc.arg('lease_token_hash'),
        lease_expires_at = sqlc.arg('lease_expires_at'),
        started_at = COALESCE(j.started_at, now()),
        completed_at = NULL,
        failure_category = NULL,
        failure_detail = NULL
    FROM candidate c
    WHERE j.id = c.id
    RETURNING j.*
), attempt AS (
    INSERT INTO target_probe_attempts (
        job_id,
        attempt_number,
        worker_id,
        lease_token_hash,
        lease_expires_at
    )
    SELECT
        l.id,
        l.attempt_count,
        l.lease_worker_id,
        l.lease_token_hash,
        l.lease_expires_at
    FROM leased l
    RETURNING id, job_id
)
SELECT
    l.id AS job_id,
    attempt.id AS attempt_id,
    l.asset_id,
    l.endpoint_revision,
    l.protocol,
    l.reason,
    l.attempt_count,
    l.max_attempts,
    l.lease_expires_at,
    CASE l.protocol
        WHEN 'ssh' THEN ssh.target_address
        WHEN 'postgres' THEN postgres.target_address
        WHEN 'rdp' THEN rdp.target_address
        ELSE ''
    END::text AS target_address
FROM leased l
JOIN attempt ON attempt.job_id = l.id
LEFT JOIN ssh_asset_config ssh ON ssh.asset_id = l.asset_id AND l.protocol = 'ssh'
LEFT JOIN postgres_asset_config postgres ON postgres.asset_id = l.asset_id AND l.protocol = 'postgres'
LEFT JOIN rdp_asset_config rdp ON rdp.asset_id = l.asset_id AND l.protocol = 'rdp';

-- name: CompleteProbeAttempt :one
WITH completed_job AS (
    UPDATE target_probe_jobs j
    SET state = CASE sqlc.arg('outcome')::text
                    WHEN 'succeeded' THEN 'succeeded'
                    ELSE 'failed'
                END,
        lease_worker_id = NULL,
        lease_token_hash = NULL,
        lease_expires_at = NULL,
        failure_category = sqlc.narg('failure_category')::text,
        failure_detail = sqlc.narg('failure_detail')::text,
        completed_at = now()
    WHERE j.id = sqlc.arg('job_id')
      AND j.state = 'leased'
      AND j.lease_worker_id = sqlc.arg('worker_id')
      AND j.lease_token_hash = sqlc.arg('lease_token_hash')
      AND j.lease_expires_at > now()
      AND sqlc.arg('outcome')::text IN ('succeeded','failed')
    RETURNING j.id, j.attempt_count
), completed_attempt AS (
    UPDATE target_probe_attempts a
    SET completed_at = now(),
        outcome = sqlc.arg('outcome'),
        failure_category = sqlc.narg('failure_category')::text,
        failure_detail = sqlc.narg('failure_detail')::text
    FROM completed_job j
    WHERE a.job_id = j.id
      AND a.attempt_number = j.attempt_count
      AND a.worker_id = sqlc.arg('worker_id')
      AND a.lease_token_hash = sqlc.arg('lease_token_hash')
      AND a.completed_at IS NULL
    RETURNING a.*
)
SELECT * FROM completed_attempt;

-- name: InsertIdentityObservation :one
INSERT INTO target_identity_observations (
    job_id,
    asset_id,
    endpoint_revision,
    worker_id,
    source,
    resolved_addresses,
    protocol_metadata,
    observed_at,
    outcome,
    failure_category,
    failure_detail
)
VALUES (
    sqlc.narg('job_id')::uuid,
    sqlc.arg('asset_id'),
    sqlc.arg('endpoint_revision'),
    sqlc.arg('worker_id'),
    sqlc.arg('source'),
    sqlc.arg('resolved_addresses'),
    sqlc.arg('protocol_metadata'),
    sqlc.arg('observed_at'),
    sqlc.arg('outcome'),
    sqlc.narg('failure_category')::text,
    sqlc.narg('failure_detail')::text
)
RETURNING *;

-- name: InsertIdentityEvidence :one
INSERT INTO target_identity_evidence (
    observation_id,
    kind,
    algorithm,
    sha256_fingerprint,
    public_material,
    certificate_subject,
    certificate_issuer,
    issuer_sha256_fingerprint,
    dns_names,
    ip_addresses,
    ssh_principals,
    serial_number,
    valid_from,
    valid_until,
    key_metadata,
    display_extensions
)
VALUES (
    sqlc.arg('observation_id'),
    sqlc.arg('kind'),
    sqlc.arg('algorithm'),
    sqlc.arg('sha256_fingerprint'),
    sqlc.arg('public_material'),
    sqlc.narg('certificate_subject')::text,
    sqlc.narg('certificate_issuer')::text,
    sqlc.narg('issuer_sha256_fingerprint')::text,
    sqlc.arg('dns_names'),
    sqlc.arg('ip_addresses'),
    sqlc.arg('ssh_principals'),
    sqlc.narg('serial_number')::text,
    sqlc.narg('valid_from')::timestamptz,
    sqlc.narg('valid_until')::timestamptz,
    sqlc.arg('key_metadata'),
    sqlc.arg('display_extensions')
)
RETURNING *;

-- name: ListCurrentActiveTrustAnchors :many
SELECT anchor.*
FROM target_trust_anchors anchor
JOIN assets asset
  ON asset.id = anchor.asset_id
 AND asset.endpoint_revision = anchor.endpoint_revision
WHERE anchor.asset_id = sqlc.arg('asset_id')
  AND anchor.revoked_at IS NULL
  AND anchor.approved_at <= now()
  AND (anchor.not_before IS NULL OR anchor.not_before <= now())
  AND (anchor.expires_at IS NULL OR anchor.expires_at > now())
ORDER BY anchor.approved_at, anchor.id;

-- name: ApproveTrustAnchor :one
INSERT INTO target_trust_anchors (
    asset_id,
    endpoint_revision,
    kind,
    algorithm,
    sha256_fingerprint,
    public_material,
    required_ssh_principals,
    required_dns_names,
    required_ip_addresses,
    source,
    observation_id,
    approved_by,
    approved_at,
    not_before,
    expires_at
)
VALUES (
    sqlc.arg('asset_id'),
    sqlc.arg('endpoint_revision'),
    sqlc.arg('kind'),
    sqlc.arg('algorithm'),
    sqlc.arg('sha256_fingerprint'),
    sqlc.arg('public_material'),
    sqlc.arg('required_ssh_principals'),
    sqlc.arg('required_dns_names'),
    sqlc.arg('required_ip_addresses'),
    sqlc.arg('source'),
    sqlc.narg('observation_id')::uuid,
    sqlc.narg('approved_by')::uuid,
    sqlc.arg('approved_at'),
    sqlc.narg('not_before')::timestamptz,
    sqlc.narg('expires_at')::timestamptz
)
RETURNING *;

-- name: RevokeTrustAnchor :one
UPDATE target_trust_anchors
SET revoked_at = sqlc.arg('revoked_at'),
    revoked_by = sqlc.narg('revoked_by')::uuid,
    revocation_reason = sqlc.narg('revocation_reason')::text
WHERE id = sqlc.arg('anchor_id')
  AND asset_id = sqlc.arg('asset_id')
  AND revoked_at IS NULL
RETURNING *;

-- name: IncrementAssetEndpointRevision :one
UPDATE assets
SET endpoint_revision = endpoint_revision + 1
WHERE id = sqlc.arg('asset_id')
RETURNING endpoint_revision;

-- name: GetAssetVerificationStatus :one
WITH current_asset AS (
    SELECT id, endpoint_revision
    FROM assets
    WHERE id = sqlc.arg('asset_id')
), latest_observation AS (
    SELECT observation.*
    FROM target_identity_observations observation
    JOIN current_asset asset
      ON asset.id = observation.asset_id
     AND asset.endpoint_revision = observation.endpoint_revision
    ORDER BY observation.observed_at DESC, observation.id DESC
    LIMIT 1
), latest_terminal_job AS (
    SELECT job.*
    FROM target_probe_jobs job
    JOIN current_asset asset
      ON asset.id = job.asset_id
     AND asset.endpoint_revision = job.endpoint_revision
    WHERE job.state IN ('succeeded','failed','superseded','cancelled')
    ORDER BY job.completed_at DESC, job.id DESC
    LIMIT 1
), active_anchor AS (
    SELECT anchor.*
    FROM target_trust_anchors anchor
    JOIN current_asset asset
      ON asset.id = anchor.asset_id
     AND asset.endpoint_revision = anchor.endpoint_revision
    WHERE anchor.revoked_at IS NULL
      AND anchor.approved_at <= now()
      AND (anchor.not_before IS NULL OR anchor.not_before <= now())
      AND (anchor.expires_at IS NULL OR anchor.expires_at > now())
), matching_identity AS (
    SELECT 1
    FROM latest_observation observation
    JOIN target_identity_evidence evidence ON evidence.observation_id = observation.id
    JOIN active_anchor anchor
      ON (
          (anchor.kind = 'ssh_host_key'
              AND evidence.kind = 'ssh_host_key'
              AND anchor.sha256_fingerprint = evidence.sha256_fingerprint)
       OR (anchor.kind = 'ssh_host_ca'
              AND evidence.kind = 'ssh_host_certificate'
              AND anchor.sha256_fingerprint = evidence.issuer_sha256_fingerprint)
       OR (anchor.kind = 'tls_leaf'
              AND evidence.kind = 'tls_leaf'
              AND anchor.sha256_fingerprint = evidence.sha256_fingerprint)
       OR (anchor.kind = 'tls_ca'
              AND evidence.kind IN ('tls_intermediate','tls_presented_root')
              AND anchor.sha256_fingerprint = evidence.sha256_fingerprint)
     )
    LIMIT 1
)
SELECT
    asset.id AS asset_id,
    asset.endpoint_revision,
    CASE
        WHEN observation.outcome = 'mismatch' THEN 'identity_changed'
        WHEN observation.outcome = 'succeeded' AND EXISTS (SELECT 1 FROM matching_identity) THEN 'verified'
        WHEN observation.outcome = 'succeeded' AND EXISTS (SELECT 1 FROM active_anchor) THEN 'identity_changed'
        WHEN observation.outcome = 'succeeded' THEN 'awaiting_approval'
        WHEN job.state = 'failed'
             AND (observation.observed_at IS NULL OR job.completed_at >= observation.observed_at)
            THEN 'probe_failed'
        ELSE 'pending_verification'
    END::text AS verification_status,
    observation.id AS latest_observation_id,
    job.id AS latest_probe_job_id
FROM current_asset asset
LEFT JOIN latest_observation observation ON true
LEFT JOIN latest_terminal_job job ON true;
