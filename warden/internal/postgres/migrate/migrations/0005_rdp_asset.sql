-- +goose Up
-- +goose StatementBegin

-- Admit "rdp" as a fourth asset kind alongside ssh/postgres/k8s.
ALTER TABLE public.assets DROP CONSTRAINT assets_kind_check;
ALTER TABLE public.assets ADD CONSTRAINT assets_kind_check
    CHECK ((kind = ANY (ARRAY['ssh'::text, 'postgres'::text, 'k8s'::text, 'rdp'::text])));

CREATE TABLE public.rdp_asset_config (
    asset_id uuid NOT NULL,
    target_address text DEFAULT ''::text NOT NULL,
    target_server_ca text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.rdp_asset_login (
    asset_id uuid NOT NULL,
    login text NOT NULL,
    kind text NOT NULL,
    secret_id uuid,
    CONSTRAINT rdp_asset_login_kind_check CHECK ((kind = ANY (ARRAY['password'::text]))),
    CONSTRAINT rdp_login_secret_present CHECK ((secret_id IS NOT NULL))
);

ALTER TABLE ONLY public.rdp_asset_config
    ADD CONSTRAINT rdp_asset_config_pkey PRIMARY KEY (asset_id);

ALTER TABLE ONLY public.rdp_asset_login
    ADD CONSTRAINT rdp_asset_login_pkey PRIMARY KEY (asset_id, login);

ALTER TABLE ONLY public.rdp_asset_config
    ADD CONSTRAINT rdp_asset_config_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rdp_asset_login
    ADD CONSTRAINT rdp_asset_login_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.rdp_asset_login
    ADD CONSTRAINT rdp_login_secret_same_asset FOREIGN KEY (asset_id, secret_id) REFERENCES public.asset_secrets(asset_id, id) ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.rdp_asset_login;
DROP TABLE IF EXISTS public.rdp_asset_config;
ALTER TABLE public.assets DROP CONSTRAINT assets_kind_check;
ALTER TABLE public.assets ADD CONSTRAINT assets_kind_check
    CHECK ((kind = ANY (ARRAY['ssh'::text, 'postgres'::text, 'k8s'::text])));
-- +goose StatementEnd
