-- +goose Up
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_kind_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_kind_check CHECK (kind IN ('ssh','x509','mesh'));

-- +goose Down
ALTER TABLE ca_keys DROP CONSTRAINT ca_keys_kind_check;
ALTER TABLE ca_keys ADD CONSTRAINT ca_keys_kind_check CHECK (kind IN ('ssh','x509'));
