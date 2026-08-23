-- +goose Up
ALTER TABLE session_recordings
    ADD COLUMN grant_id uuid REFERENCES access_grants(id) ON DELETE SET NULL;
CREATE INDEX session_recordings_grant_idx ON session_recordings (grant_id) WHERE grant_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS session_recordings_grant_idx;
ALTER TABLE session_recordings DROP COLUMN IF EXISTS grant_id;
