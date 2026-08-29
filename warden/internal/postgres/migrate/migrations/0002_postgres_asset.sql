-- +goose Up
-- +goose StatementBegin

CREATE TABLE public.postgres_asset_config (
    asset_id uuid NOT NULL,
    target_address text DEFAULT ''::text NOT NULL,
    target_server_ca text DEFAULT ''::text NOT NULL,
    default_database text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.postgres_asset_login (
    asset_id uuid NOT NULL,
    role text NOT NULL,
    kind text NOT NULL,
    secret_id uuid,
    CONSTRAINT postgres_asset_login_kind_check CHECK ((kind = ANY (ARRAY['mtls'::text, 'password'::text]))),
    CONSTRAINT postgres_login_secret_present CHECK (((kind = 'mtls'::text) OR (secret_id IS NOT NULL)))
);

ALTER TABLE ONLY public.postgres_asset_config
    ADD CONSTRAINT postgres_asset_config_pkey PRIMARY KEY (asset_id);

ALTER TABLE ONLY public.postgres_asset_login
    ADD CONSTRAINT postgres_asset_login_pkey PRIMARY KEY (asset_id, role);

ALTER TABLE ONLY public.postgres_asset_config
    ADD CONSTRAINT postgres_asset_config_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.postgres_asset_login
    ADD CONSTRAINT postgres_asset_login_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.postgres_asset_login
    ADD CONSTRAINT postgres_login_secret_same_asset FOREIGN KEY (asset_id, secret_id) REFERENCES public.asset_secrets(asset_id, id) ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.postgres_asset_login;
DROP TABLE IF EXISTS public.postgres_asset_config;
-- +goose StatementEnd
