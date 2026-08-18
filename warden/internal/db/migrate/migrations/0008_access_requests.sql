-- +goose Up
ALTER TABLE request_policies ADD COLUMN max_duration interval;   -- NULL => global default cap

-- +goose StatementBegin
DO $$
DECLARE cname text;
BEGIN
  SELECT conname INTO cname FROM pg_constraint
   WHERE conrelid = 'request_policies'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) ILIKE '%required_approvals%';
  IF cname IS NOT NULL THEN EXECUTE format('ALTER TABLE request_policies DROP CONSTRAINT %I', cname); END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE request_policies ADD CONSTRAINT request_policies_required_approvals_check CHECK (required_approvals >= 0);

CREATE TABLE access_requests (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_user_id  uuid NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    role_id            uuid NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
    asset_id           uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    reason             text NOT NULL DEFAULT '',
    requested_duration interval NOT NULL,
    required_approvals int  NOT NULL,
    granted_duration   interval NOT NULL,
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','granted','denied','cancelled')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz
);
CREATE UNIQUE INDEX uq_pending_request ON access_requests (requester_user_id, role_id, asset_id) WHERE status = 'pending';
CREATE INDEX idx_access_requests_requester ON access_requests (requester_user_id);

CREATE TABLE access_request_approvals (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id       uuid NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    approver_user_id uuid NOT NULL REFERENCES users(id)           ON DELETE CASCADE,
    decision         text NOT NULL CHECK (decision IN ('approve','deny')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (request_id, approver_user_id)
);

CREATE TABLE access_grants (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      uuid NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    role_id         uuid NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
    scope_asset_id  uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    subject_user_id uuid NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    revoked_reason  text,
    UNIQUE (request_id)
);
CREATE INDEX idx_access_grants_active ON access_grants (subject_user_id) WHERE revoked_at IS NULL;

-- +goose Down
DROP TABLE access_grants;
DROP TABLE access_request_approvals;
DROP TABLE access_requests;
-- +goose StatementBegin
DO $$
DECLARE cname text;
BEGIN
  SELECT conname INTO cname FROM pg_constraint
   WHERE conrelid = 'request_policies'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) ILIKE '%required_approvals%';
  IF cname IS NOT NULL THEN EXECUTE format('ALTER TABLE request_policies DROP CONSTRAINT %I', cname); END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE request_policies ADD CONSTRAINT request_policies_required_approvals_check CHECK (required_approvals >= 1);
ALTER TABLE request_policies DROP COLUMN max_duration;
