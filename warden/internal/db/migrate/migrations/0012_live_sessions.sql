-- +goose Up
ALTER TABLE ssh_asset_config ADD COLUMN target_address text NOT NULL DEFAULT '';

CREATE TABLE live_sessions (
    id                     uuid PRIMARY KEY,        -- = token jti (replay guard)
    user_id                uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset_id               uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    worker_id              text NOT NULL,
    grant_id               uuid REFERENCES access_grants(id) ON DELETE SET NULL,
    protocol               text NOT NULL,
    principals             text[] NOT NULL,
    client_key_fp          text NOT NULL,
    started_at             timestamptz NOT NULL DEFAULT now(),
    terminate_requested_at timestamptz
);
CREATE INDEX idx_live_sessions_worker ON live_sessions (worker_id);
CREATE INDEX idx_live_sessions_user_asset ON live_sessions (user_id, asset_id);
CREATE INDEX idx_live_sessions_grant ON live_sessions (grant_id);

-- +goose Down
DROP TABLE live_sessions;
ALTER TABLE ssh_asset_config DROP COLUMN target_address;
