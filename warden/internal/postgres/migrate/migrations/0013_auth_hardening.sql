-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.auth_tokens
    ADD COLUMN last_used_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN client_ip    text,
    ADD COLUMN user_agent   text,
    ADD COLUMN label        text;

-- Case-insensitive login identity: reject duplicate emails that differ only in case.
-- Up will fail if any two existing users' emails already differ only by case;
-- acceptable pre-production.
CREATE UNIQUE INDEX users_email_lower_key ON public.users (lower(email));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS public.users_email_lower_key;
ALTER TABLE public.auth_tokens
    DROP COLUMN IF EXISTS last_used_at,
    DROP COLUMN IF EXISTS client_ip,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS label;
-- +goose StatementEnd
