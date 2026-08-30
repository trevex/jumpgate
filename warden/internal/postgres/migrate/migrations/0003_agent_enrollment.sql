-- +goose Up
-- +goose StatementBegin
CREATE TABLE public.agent_enrollment_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    asset_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.agent_enrollment_tokens
    ADD CONSTRAINT agent_enrollment_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_enrollment_tokens
    ADD CONSTRAINT agent_enrollment_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.agent_enrollment_tokens
    ADD CONSTRAINT agent_enrollment_tokens_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.agent_enrollment_tokens;
-- +goose StatementEnd
