-- Periodic-probe scheduling and the durable notification outbox.

-- name: UpsertProbeSchedule :one
INSERT INTO target_identity_probe_schedules (
    asset_id, probe_interval_seconds, freshness_seconds, enabled
) VALUES (
    sqlc.arg('asset_id'), sqlc.arg('probe_interval_seconds'),
    sqlc.narg('freshness_seconds')::bigint, sqlc.arg('enabled')
)
ON CONFLICT (asset_id) DO UPDATE
SET probe_interval_seconds = excluded.probe_interval_seconds,
    freshness_seconds = excluded.freshness_seconds,
    enabled = excluded.enabled,
    updated_at = now()
RETURNING *;

-- name: GetProbeSchedule :one
SELECT * FROM target_identity_probe_schedules WHERE asset_id = sqlc.arg('asset_id');

-- ListDuePeriodicProbes selects assets whose enabled schedule is due for a fresh
-- periodic probe against their CURRENT endpoint revision: no active (queued/leased)
-- periodic probe exists, and the most recent observation for that revision (if any)
-- is older than the per-asset probe interval measured from the supplied reference
-- time. FOR UPDATE SKIP LOCKED partitions due rows across concurrent schedulers so
-- replicas claim disjoint batches; the partial unique index is the correctness
-- backstop against duplicate current-revision jobs.
-- name: ListDuePeriodicProbes :many
SELECT s.asset_id, a.endpoint_revision
FROM target_identity_probe_schedules s
JOIN assets a ON a.id = s.asset_id
WHERE s.enabled
  AND a.kind IN ('ssh','postgres','rdp','k8s')
  AND NOT EXISTS (
      SELECT 1 FROM target_probe_jobs j
      WHERE j.asset_id = s.asset_id
        AND j.endpoint_revision = a.endpoint_revision
        AND j.reason = 'periodic'
        AND j.state IN ('queued','leased')
  )
  AND COALESCE(
        (SELECT max(o.observed_at)
         FROM target_identity_observations o
         WHERE o.asset_id = s.asset_id
           AND o.endpoint_revision = a.endpoint_revision),
        'epoch'::timestamptz
      ) < sqlc.arg('at_time')::timestamptz - (s.probe_interval_seconds * interval '1 second')
ORDER BY s.asset_id
FOR UPDATE OF s SKIP LOCKED
LIMIT sqlc.arg('batch');

-- name: EnqueueNotification :exec
INSERT INTO notification_outbox (idempotency_key, kind, subject, payload, max_attempts, next_delivery_at)
VALUES (
    sqlc.arg('idempotency_key'), sqlc.arg('kind'), sqlc.arg('subject'),
    sqlc.arg('payload'), sqlc.arg('max_attempts'), sqlc.arg('next_delivery_at')
)
ON CONFLICT (idempotency_key) DO NOTHING;

-- name: ListDueNotifications :many
SELECT id, idempotency_key, kind, subject, payload, attempts, max_attempts
FROM notification_outbox
WHERE state = 'pending'
  AND next_delivery_at <= sqlc.arg('at_time')::timestamptz
ORDER BY next_delivery_at, seq
LIMIT sqlc.arg('batch')
FOR UPDATE SKIP LOCKED;

-- name: MarkNotificationDelivered :exec
UPDATE notification_outbox
SET state = 'delivered', attempts = attempts + 1, delivered_at = sqlc.arg('delivered_at'), last_error = NULL
WHERE id = sqlc.arg('id');

-- RescheduleNotification records one failed delivery attempt. It goes terminal
-- ('failed') once attempts reach max_attempts, otherwise stays 'pending' with a
-- caller-computed backoff deadline. It NEVER touches authorization or identity state.
-- name: RescheduleNotification :exec
UPDATE notification_outbox
SET attempts = attempts + 1,
    last_error = sqlc.arg('last_error'),
    state = CASE WHEN attempts + 1 >= max_attempts THEN 'failed' ELSE 'pending' END,
    next_delivery_at = sqlc.arg('next_delivery_at')
WHERE id = sqlc.arg('id');

-- name: CountPendingNotifications :one
SELECT count(*) FROM notification_outbox WHERE state = 'pending';

-- ListUnresolvedMismatches returns current-revision mismatch observations for
-- enabled schedules that are neither approved (an active anchor tied to the exact
-- observation) nor explicitly rejected (an observation_rejected audit event).
-- name: ListUnresolvedMismatches :many
SELECT o.asset_id, o.endpoint_revision, o.id AS observation_id
FROM target_identity_probe_schedules s
JOIN assets a ON a.id = s.asset_id
JOIN target_identity_observations o
  ON o.asset_id = s.asset_id AND o.endpoint_revision = a.endpoint_revision
WHERE s.enabled
  AND o.outcome = 'mismatch'
  AND NOT EXISTS (
      SELECT 1 FROM target_trust_anchors ta
      WHERE ta.asset_id = o.asset_id
        AND ta.endpoint_revision = o.endpoint_revision
        AND ta.observation_id = o.id
        AND ta.revoked_at IS NULL
        AND ta.approved_at <= sqlc.arg('at_time')::timestamptz
        AND (ta.not_before IS NULL OR ta.not_before <= sqlc.arg('at_time')::timestamptz)
        AND (ta.expires_at IS NULL OR ta.expires_at > sqlc.arg('at_time')::timestamptz)
  )
  AND NOT EXISTS (
      SELECT 1 FROM audit_outbox
      WHERE event_type = 'target_identity.observation_rejected'
        AND subject = 'asset:' || o.asset_id::text
        AND details->>'observation_id' = o.id::text
  )
  AND NOT EXISTS (
      SELECT 1 FROM audit_log
      WHERE event_type = 'target_identity.observation_rejected'
        AND subject = 'asset:' || o.asset_id::text
        AND details->>'observation_id' = o.id::text
  );

-- ListRepeatedProbeFailures returns enabled schedules whose current revision has
-- accumulated at least the threshold of failed probe jobs since the last successful
-- observation. This is the connectivity-degraded signal: it drives a notification
-- but never a trust change.
-- name: ListRepeatedProbeFailures :many
SELECT s.asset_id,
       a.endpoint_revision,
       fail.failure_count::bigint AS failure_count,
       fail.latest_failed_job_id::uuid AS latest_failed_job_id
FROM target_identity_probe_schedules s
JOIN assets a ON a.id = s.asset_id
JOIN LATERAL (
    SELECT count(*) AS failure_count,
           (array_agg(j.id ORDER BY j.completed_at DESC, j.id DESC))[1] AS latest_failed_job_id
    FROM target_probe_jobs j
    WHERE j.asset_id = s.asset_id
      AND j.endpoint_revision = a.endpoint_revision
      AND j.state = 'failed'
      AND j.completed_at > COALESCE((
          SELECT max(o.observed_at)
          FROM target_identity_observations o
          WHERE o.asset_id = s.asset_id
            AND o.endpoint_revision = a.endpoint_revision
            AND o.outcome = 'succeeded'
      ), 'epoch'::timestamptz)
) fail ON true
WHERE s.enabled
  AND fail.failure_count >= sqlc.arg('threshold')::bigint;

-- ListApproachingAnchorExpiry returns active anchors on enabled schedules whose
-- expires_at falls inside the warning window ahead of the reference time.
-- name: ListApproachingAnchorExpiry :many
SELECT ta.asset_id, ta.endpoint_revision, ta.id AS anchor_id, ta.expires_at
FROM target_trust_anchors ta
JOIN target_identity_probe_schedules s ON s.asset_id = ta.asset_id
JOIN assets a ON a.id = ta.asset_id AND a.endpoint_revision = ta.endpoint_revision
WHERE s.enabled
  AND ta.revoked_at IS NULL
  AND ta.expires_at IS NOT NULL
  AND ta.approved_at <= sqlc.arg('at_time')::timestamptz
  AND (ta.not_before IS NULL OR ta.not_before <= sqlc.arg('at_time')::timestamptz)
  AND ta.expires_at > sqlc.arg('at_time')::timestamptz
  AND ta.expires_at <= sqlc.arg('at_time')::timestamptz + (sqlc.arg('warn_seconds')::bigint * interval '1 second');

-- ListApproachingFreshnessExpiry returns enabled schedules with a freshness policy
-- whose latest successful observation is about to age past the freshness window
-- (its derived expiry falls inside the warning window ahead of the reference time).
-- name: ListApproachingFreshnessExpiry :many
SELECT s.asset_id,
       a.endpoint_revision,
       (last.observed_at + (s.freshness_seconds * interval '1 second'))::timestamptz AS expires_at
FROM target_identity_probe_schedules s
JOIN assets a ON a.id = s.asset_id
JOIN LATERAL (
    SELECT max(o.observed_at) AS observed_at
    FROM target_identity_observations o
    WHERE o.asset_id = s.asset_id
      AND o.endpoint_revision = a.endpoint_revision
      AND o.outcome = 'succeeded'
) last ON true
WHERE s.enabled
  AND s.freshness_seconds IS NOT NULL
  AND last.observed_at IS NOT NULL
  AND (last.observed_at + (s.freshness_seconds * interval '1 second')) > sqlc.arg('at_time')::timestamptz
  AND (last.observed_at + (s.freshness_seconds * interval '1 second')) <= sqlc.arg('at_time')::timestamptz + (sqlc.arg('warn_seconds')::bigint * interval '1 second');
