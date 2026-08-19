-- +goose Up
CREATE TABLE session_recordings (
    session_id   uuid PRIMARY KEY,
    user_id      uuid NOT NULL,
    asset_id     uuid NOT NULL,
    worker_id    text NOT NULL,
    protocol     text NOT NULL,
    format       text NOT NULL,
    object_key   text NOT NULL,
    size_bytes   bigint NOT NULL DEFAULT 0,
    sha256       text NOT NULL DEFAULT '',
    status       text NOT NULL,
    started_at   timestamptz,
    ended_at     timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_recordings_user_idx  ON session_recordings (user_id, created_at DESC);
CREATE INDEX session_recordings_asset_idx ON session_recordings (asset_id, created_at DESC);

-- +goose Down
DROP TABLE session_recordings;
