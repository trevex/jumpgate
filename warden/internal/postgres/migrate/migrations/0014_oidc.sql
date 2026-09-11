-- +goose Up
-- +goose StatementBegin
CREATE TABLE public.user_identities (
    id         uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    issuer     text NOT NULL,
    subject    text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT uq_user_identity UNIQUE (issuer, subject)
);
CREATE INDEX idx_user_identities_user ON public.user_identities (user_id);

ALTER TABLE public.groups ADD COLUMN external_key text;
CREATE UNIQUE INDEX uq_group_external_key ON public.groups (external_key) WHERE external_key IS NOT NULL;

ALTER TABLE public.group_memberships
    ADD COLUMN origin text NOT NULL DEFAULT 'manual'
    CONSTRAINT group_memberships_origin_check CHECK (origin IN ('manual','oidc'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.group_memberships DROP COLUMN IF EXISTS origin;
DROP INDEX IF EXISTS public.uq_group_external_key;
ALTER TABLE public.groups DROP COLUMN IF EXISTS external_key;
DROP TABLE IF EXISTS public.user_identities;
-- +goose StatementEnd
