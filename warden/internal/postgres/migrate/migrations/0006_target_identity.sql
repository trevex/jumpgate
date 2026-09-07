-- +goose Up
-- +goose StatementBegin

ALTER TABLE assets ADD COLUMN endpoint_revision bigint NOT NULL DEFAULT 1
    CHECK (endpoint_revision > 0);

CREATE TABLE target_probe_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    previous_job_id uuid REFERENCES target_probe_jobs(id),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    endpoint_revision bigint NOT NULL CHECK (endpoint_revision > 0),
    protocol text NOT NULL CHECK (protocol IN ('ssh','postgres','rdp','k8s')),
    state text NOT NULL CHECK (state IN ('queued','leased','succeeded','failed','superseded','cancelled')),
    reason text NOT NULL CHECK (reason IN ('onboarding','manual','periodic','endpoint_changed','session_mismatch')),
    requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_worker_id text,
    lease_token_hash bytea,
    lease_expires_at timestamptz,
    failure_category text,
    failure_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    CONSTRAINT target_probe_jobs_id_asset_revision_key UNIQUE (id, asset_id, endpoint_revision),
    CONSTRAINT target_probe_jobs_lease_hash_length CHECK (
        lease_token_hash IS NULL OR octet_length(lease_token_hash) = 32
    ),
    CONSTRAINT target_probe_jobs_lease_shape CHECK (
        (state = 'leased' AND lease_worker_id IS NOT NULL AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state <> 'leased' AND lease_worker_id IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT target_probe_jobs_completion_shape CHECK (
        (state IN ('succeeded','failed','superseded','cancelled')) = (completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX target_probe_jobs_one_active_onboarding
    ON target_probe_jobs (asset_id, endpoint_revision)
    WHERE reason IN ('onboarding','endpoint_changed') AND state IN ('queued','leased');

CREATE INDEX target_probe_jobs_claim_order
    ON target_probe_jobs (next_attempt_at, created_at, id)
    WHERE state = 'queued';

CREATE INDEX target_probe_jobs_asset_history
    ON target_probe_jobs (asset_id, created_at DESC, id DESC);

CREATE TABLE target_probe_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL REFERENCES target_probe_jobs(id) ON DELETE CASCADE,
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    worker_id text NOT NULL CHECK (worker_id <> ''),
    lease_token_hash bytea NOT NULL CHECK (octet_length(lease_token_hash) = 32),
    lease_expires_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    outcome text CHECK (outcome IN ('succeeded','failed','lease_expired','cancelled')),
    failure_category text,
    failure_detail text,
    CONSTRAINT target_probe_attempts_job_number_key UNIQUE (job_id, attempt_number),
    CONSTRAINT target_probe_attempts_completion_shape CHECK (
        (completed_at IS NULL AND outcome IS NULL)
        OR
        (completed_at IS NOT NULL AND outcome IS NOT NULL)
    )
);

CREATE TABLE target_identity_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id uuid,
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    endpoint_revision bigint NOT NULL CHECK (endpoint_revision > 0),
    worker_id text NOT NULL CHECK (worker_id <> ''),
    source text NOT NULL CHECK (source IN ('probe','session_mismatch')),
    resolved_addresses jsonb NOT NULL,
    protocol_metadata jsonb NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    outcome text NOT NULL CHECK (outcome IN ('succeeded','failed','mismatch','stale')),
    validation_state text NOT NULL DEFAULT 'unvalidated'
        CHECK (validation_state IN ('unvalidated','validated','failed')),
    failure_category text,
    failure_detail text,
    CONSTRAINT target_identity_observations_id_asset_revision_key
        UNIQUE (id, asset_id, endpoint_revision),
    CONSTRAINT target_identity_observations_job_fkey
        FOREIGN KEY (job_id, asset_id, endpoint_revision)
        REFERENCES target_probe_jobs(id, asset_id, endpoint_revision) ON DELETE SET NULL (job_id),
    CONSTRAINT target_identity_observations_addresses_array CHECK (jsonb_typeof(resolved_addresses) = 'array'),
    CONSTRAINT target_identity_observations_metadata_object CHECK (jsonb_typeof(protocol_metadata) = 'object')
);

CREATE INDEX target_identity_observations_asset_revision
    ON target_identity_observations (asset_id, endpoint_revision, observed_at DESC, id DESC);

CREATE TABLE target_identity_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    observation_id uuid NOT NULL REFERENCES target_identity_observations(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('ssh_host_key','ssh_host_certificate','tls_leaf','tls_intermediate','tls_presented_root')),
    algorithm text NOT NULL CHECK (algorithm <> ''),
    sha256_fingerprint text NOT NULL CHECK (sha256_fingerprint <> ''),
    public_material text NOT NULL CHECK (public_material <> ''),
    certificate_subject text,
    certificate_issuer text,
    issuer_sha256_fingerprint text,
    dns_names text[] NOT NULL DEFAULT '{}',
    ip_addresses text[] NOT NULL DEFAULT '{}',
    ssh_principals text[] NOT NULL DEFAULT '{}',
    serial_number text,
    valid_from timestamptz,
    valid_until timestamptz,
    key_metadata jsonb NOT NULL DEFAULT '{}',
    display_extensions jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT target_identity_evidence_observation_kind_fingerprint_key
        UNIQUE (observation_id, kind, sha256_fingerprint),
    CONSTRAINT target_identity_evidence_id_observation_key
        UNIQUE (id, observation_id),
    CONSTRAINT target_identity_evidence_validity CHECK (
        valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from
    ),
    CONSTRAINT target_identity_evidence_key_metadata_object CHECK (jsonb_typeof(key_metadata) = 'object'),
    CONSTRAINT target_identity_evidence_extensions_object CHECK (jsonb_typeof(display_extensions) = 'object')
);

CREATE INDEX target_identity_evidence_fingerprint
    ON target_identity_evidence (kind, sha256_fingerprint);

CREATE TABLE target_trust_anchors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    endpoint_revision bigint NOT NULL CHECK (endpoint_revision > 0),
    kind text NOT NULL CHECK (kind IN ('ssh_host_key','ssh_host_ca','tls_ca','tls_leaf')),
    algorithm text NOT NULL DEFAULT '',
    sha256_fingerprint text NOT NULL CHECK (sha256_fingerprint <> ''),
    public_material text NOT NULL CHECK (public_material <> ''),
    required_ssh_principals text[] NOT NULL DEFAULT '{}',
    required_dns_names text[] NOT NULL DEFAULT '{}',
    required_ip_addresses text[] NOT NULL DEFAULT '{}',
    source text NOT NULL CHECK (source IN ('manual','expected','tofu','migration')),
    observation_id uuid,
    approved_by uuid REFERENCES users(id) ON DELETE SET NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    not_before timestamptz,
    expires_at timestamptz,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users(id) ON DELETE SET NULL,
    revocation_reason text,
    CONSTRAINT target_trust_anchors_observation_fkey
        FOREIGN KEY (observation_id, asset_id, endpoint_revision)
        REFERENCES target_identity_observations(id, asset_id, endpoint_revision) ON DELETE SET NULL (observation_id),
    CONSTRAINT target_trust_anchors_id_asset_revision_key
        UNIQUE (id, asset_id, endpoint_revision),
    CONSTRAINT target_trust_anchors_validity CHECK (
        not_before IS NULL OR expires_at IS NULL OR expires_at > not_before
    ),
    CONSTRAINT target_trust_anchors_revocation_shape CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR revoked_at IS NOT NULL
    )
);

-- A validation fact is the durable proof that this exact observed leaf was
-- validated to this exact approved anchor. A TLS root need not be presented:
-- the approved anchor is the trust root, and its absence from evidence is
-- represented by the lack of a root evidence row rather than a failed proof.
CREATE TABLE target_identity_validation_facts (
    observation_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    endpoint_revision bigint NOT NULL CHECK (endpoint_revision > 0),
    anchor_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    validated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (observation_id, anchor_id, evidence_id),
    CONSTRAINT target_identity_validation_observation_fkey
        FOREIGN KEY (observation_id, asset_id, endpoint_revision)
        REFERENCES target_identity_observations(id, asset_id, endpoint_revision) ON DELETE CASCADE,
    CONSTRAINT target_identity_validation_anchor_fkey
        FOREIGN KEY (anchor_id, asset_id, endpoint_revision)
        REFERENCES target_trust_anchors(id, asset_id, endpoint_revision) ON DELETE CASCADE,
    CONSTRAINT target_identity_validation_evidence_fkey
        FOREIGN KEY (evidence_id, observation_id)
        REFERENCES target_identity_evidence(id, observation_id) ON DELETE CASCADE
);

CREATE INDEX target_identity_validation_facts_lookup
    ON target_identity_validation_facts (observation_id, anchor_id, evidence_id);

CREATE INDEX target_trust_anchors_active
    ON target_trust_anchors (asset_id, endpoint_revision, kind, approved_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX target_trust_anchors_fingerprint
    ON target_trust_anchors (kind, sha256_fingerprint);

CREATE INDEX target_trust_anchors_asset_history
    ON target_trust_anchors (asset_id, approved_at DESC, id DESC);

-- Public mutation request IDs are durable idempotency keys. The request hash
-- binds one UUID to one operation, actor, asset, and canonical payload; response
-- stores the original logical result for exact replay.
CREATE TABLE target_identity_mutation_requests (
    request_id uuid PRIMARY KEY,
    operation text NOT NULL,
    asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT target_identity_mutation_response_object CHECK (
        response IS NULL OR jsonb_typeof(response) = 'object'
    )
);

CREATE FUNCTION cleanup_target_identity_for_asset() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Completed attempts and observations are immutable except while this trigger
    -- performs the deliberate history cleanup owned by an asset deletion. The
    -- marker is transaction-local, reset before returning, and is also coupled to
    -- nested trigger depth by the immutable-row triggers below.
    PERFORM set_config('jumpgate.target_identity_asset_cleanup', 'on', true);
    DELETE FROM target_trust_anchors WHERE asset_id = OLD.id;
    DELETE FROM target_identity_observations WHERE asset_id = OLD.id;
    DELETE FROM target_probe_jobs WHERE asset_id = OLD.id;
    PERFORM set_config('jumpgate.target_identity_asset_cleanup', 'off', true);
    RETURN OLD;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('jumpgate.target_identity_asset_cleanup', 'off', true);
    RAISE;
END;
$$;

CREATE TRIGGER assets_cleanup_target_identity
BEFORE DELETE ON assets
FOR EACH ROW EXECUTE FUNCTION cleanup_target_identity_for_asset();

CREATE FUNCTION reject_completed_target_probe_attempt_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.completed_at IS NOT NULL
       AND NOT (
           TG_OP = 'DELETE'
           AND pg_trigger_depth() > 1
           AND COALESCE(current_setting('jumpgate.target_identity_asset_cleanup', true), 'off') = 'on'
       ) THEN
        RAISE EXCEPTION 'completed target probe attempts are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER target_probe_attempts_immutable_when_completed
BEFORE UPDATE OR DELETE ON target_probe_attempts
FOR EACH ROW EXECUTE FUNCTION reject_completed_target_probe_attempt_mutation();

CREATE FUNCTION reject_target_identity_observation_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (
        TG_OP = 'DELETE'
        AND pg_trigger_depth() > 1
        AND COALESCE(current_setting('jumpgate.target_identity_asset_cleanup', true), 'off') = 'on'
    ) THEN
        RAISE EXCEPTION 'target identity observations are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER target_identity_observations_immutable
BEFORE UPDATE OR DELETE ON target_identity_observations
FOR EACH ROW EXECUTE FUNCTION reject_target_identity_observation_mutation();

CREATE FUNCTION reject_target_identity_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (
        TG_OP = 'DELETE'
        AND pg_trigger_depth() > 1
        AND COALESCE(current_setting('jumpgate.target_identity_asset_cleanup', true), 'off') = 'on'
    ) THEN
        RAISE EXCEPTION 'target identity evidence is immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER target_identity_evidence_immutable
BEFORE UPDATE OR DELETE ON target_identity_evidence
FOR EACH ROW EXECUTE FUNCTION reject_target_identity_evidence_mutation();

CREATE FUNCTION reject_target_identity_validation_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (
        TG_OP = 'DELETE'
        AND pg_trigger_depth() > 1
        AND COALESCE(current_setting('jumpgate.target_identity_asset_cleanup', true), 'off') = 'on'
    ) THEN
        RAISE EXCEPTION 'target identity validation facts are immutable';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER target_identity_validation_facts_immutable
BEFORE UPDATE OR DELETE ON target_identity_validation_facts
FOR EACH ROW EXECUTE FUNCTION reject_target_identity_validation_mutation();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS assets_cleanup_target_identity ON assets;
DROP TABLE IF EXISTS target_identity_mutation_requests;
DROP TABLE IF EXISTS target_identity_validation_facts;
DROP TABLE IF EXISTS target_trust_anchors;
DROP TABLE IF EXISTS target_identity_evidence;
DROP TABLE IF EXISTS target_identity_observations;
DROP TABLE IF EXISTS target_probe_attempts;
DROP TABLE IF EXISTS target_probe_jobs;
DROP FUNCTION IF EXISTS reject_target_identity_evidence_mutation();
DROP FUNCTION IF EXISTS reject_target_identity_validation_mutation();
DROP FUNCTION IF EXISTS reject_target_identity_observation_mutation();
DROP FUNCTION IF EXISTS reject_completed_target_probe_attempt_mutation();
DROP FUNCTION IF EXISTS cleanup_target_identity_for_asset();
ALTER TABLE assets DROP COLUMN IF EXISTS endpoint_revision;
-- +goose StatementEnd
