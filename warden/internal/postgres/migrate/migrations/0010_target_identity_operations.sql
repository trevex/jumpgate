-- +goose Up
-- +goose StatementBegin

-- Per-asset periodic-probe policy. A row here opts an asset into continuous
-- monitoring; without one, an asset is never periodically probed (periodic
-- probing is off by default, both globally via config and per-asset here).
-- Durations are stored as whole seconds to keep the Go side free of interval
-- decoding; SQL multiplies by interval '1 second' for time arithmetic.
CREATE TABLE target_identity_probe_schedules (
    asset_id uuid PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    probe_interval_seconds bigint NOT NULL CHECK (probe_interval_seconds > 0),
    -- Optional freshness policy: how long a successful verification stays fresh
    -- before it should be re-probed. NULL means no freshness expiry for the asset.
    freshness_seconds bigint CHECK (freshness_seconds IS NULL OR freshness_seconds > 0),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Duplicate-probe guard for the periodic reason, mirroring the onboarding guard
-- in 0006: at most one active (queued/leased) periodic probe per asset endpoint
-- revision. Queueing a second is rejected as a unique violation (ErrProbeAlreadyQueued),
-- so concurrent schedulers across replicas never create duplicate current-revision jobs.
CREATE UNIQUE INDEX target_probe_jobs_one_active_periodic
    ON target_probe_jobs (asset_id, endpoint_revision)
    WHERE reason = 'periodic' AND state IN ('queued','leased');

-- Durable, transactional notification outbox. Producers enqueue an event inside
-- the transaction that observes the durable state (identity mismatch, repeated
-- probe failure, approaching expiry); a background drainer delivers it at least
-- once via a replaceable adapter. The idempotency_key deduplicates producers
-- (ON CONFLICT DO NOTHING) and is the downstream de-dup key. Delivery is
-- best-effort: it NEVER mutates authorization or identity state — a stuck outbox
-- cannot block or weaken enforcement.
CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq bigint GENERATED ALWAYS AS IDENTITY,
    idempotency_key text NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    kind text NOT NULL CHECK (kind IN ('identity_mismatch','repeated_probe_failure','approaching_expiry')),
    subject text NOT NULL DEFAULT '',
    payload jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(payload) = 'object'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 8 CHECK (max_attempts >= 1),
    next_delivery_at timestamptz NOT NULL DEFAULT now(),
    -- pending: eligible for (re)delivery once next_delivery_at elapses. delivered
    -- and failed are terminal (success / exhausted retries).
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','failed')),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    CONSTRAINT notification_outbox_terminal_shape CHECK (
        (state = 'delivered') = (delivered_at IS NOT NULL)
    )
);

CREATE INDEX notification_outbox_due
    ON notification_outbox (next_delivery_at, seq)
    WHERE state = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS notification_outbox;
DROP INDEX IF EXISTS target_probe_jobs_one_active_periodic;
DROP TABLE IF EXISTS target_identity_probe_schedules;
-- +goose StatementEnd
