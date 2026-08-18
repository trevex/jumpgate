-- +goose Up
DELETE FROM role_bindings WHERE kind = 'requestable';
ALTER TABLE role_bindings DROP COLUMN kind;   -- inline CHECK drops with the column
-- +goose Down
ALTER TABLE role_bindings ADD COLUMN kind text NOT NULL DEFAULT 'standing'
    CHECK (kind IN ('standing','requestable'));
ALTER TABLE role_bindings ALTER COLUMN kind DROP DEFAULT;
