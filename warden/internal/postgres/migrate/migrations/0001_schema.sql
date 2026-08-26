-- +goose Up
-- +goose StatementBegin

-- Jumpgate is pre-production. This migration is the canonical fresh-install
-- schema; it intentionally contains no upgrade backfills or legacy object names.

CREATE EXTENSION IF NOT EXISTS ltree WITH SCHEMA public;

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE FUNCTION public.folders_move_path_ids() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE new_self ltree; parent_path ltree;
BEGIN
    IF NEW.parent_id IS NULL THEN
        new_self := replace(NEW.id::text, '-', '')::ltree;
    ELSE
        SELECT path_ids INTO parent_path FROM folders WHERE id = NEW.parent_id;
        new_self := parent_path || replace(NEW.id::text, '-', '');
    END IF;
    UPDATE folders
       SET path_ids = CASE
           WHEN path_ids = OLD.path_ids THEN new_self
           ELSE new_self || subpath(path_ids, nlevel(OLD.path_ids))
       END
     WHERE path_ids <@ OLD.path_ids;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.folders_set_path_ids() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE parent_path ltree;
BEGIN
    IF NEW.parent_id IS NULL THEN
        NEW.path_ids := replace(NEW.id::text, '-', '')::ltree;
    ELSE
        SELECT path_ids INTO parent_path FROM folders WHERE id = NEW.parent_id;
        NEW.path_ids := parent_path || replace(NEW.id::text, '-', '');
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.notify_authz_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('authz_changed', '');
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.notify_authz_changed_binding_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- A user-subject binding affects exactly that user; a group-subject binding is
    -- transitive (every direct and nested member) → full sweep.
    IF OLD.subject_user_id IS NOT NULL THEN
        PERFORM pg_notify('authz_changed', OLD.subject_user_id::text);
    ELSE
        PERFORM pg_notify('authz_changed', '');
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.notify_authz_changed_membership_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- A direct user membership affects exactly that user; a nested group membership
    -- (member_group_id) has a transitive blast radius → full sweep.
    IF OLD.member_user_id IS NOT NULL THEN
        PERFORM pg_notify('authz_changed', OLD.member_user_id::text);
    ELSE
        PERFORM pg_notify('authz_changed', '');
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.notify_authz_changed_user_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- A user row change affects exactly that user.
    PERFORM pg_notify('authz_changed', OLD.id::text);
    RETURN NULL;
END;
$$;

CREATE TABLE public.access_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    role_id uuid NOT NULL,
    scope_asset_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    granted_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by uuid,
    revoked_reason text
);

CREATE TABLE public.access_request_approvals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    approver_user_id uuid NOT NULL,
    decision text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT access_request_approvals_decision_check CHECK ((decision = ANY (ARRAY['approve'::text, 'deny'::text])))
);

CREATE TABLE public.access_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    requester_user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    requested_duration interval NOT NULL,
    required_approvals integer NOT NULL,
    granted_duration interval NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    resolved_at timestamptz,
    CONSTRAINT access_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'granted'::text, 'denied'::text, 'cancelled'::text])))
);

CREATE TABLE public.asset_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    asset_id uuid NOT NULL,
    name text NOT NULL,
    sealed bytea NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL
);

CREATE TABLE public.assets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    folder_id uuid NOT NULL,
    name text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    kind text DEFAULT 'ssh'::text NOT NULL,
    CONSTRAINT assets_kind_check CHECK ((kind = ANY (ARRAY['ssh'::text, 'postgres'::text, 'k8s'::text]))),
    CONSTRAINT assets_name_canon CHECK ((name ~ '^[a-z0-9_-]+$'::text))
);

CREATE TABLE public.audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    event_type text NOT NULL,
    actor_user_id uuid,
    subject text DEFAULT ''::text NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    prev_hash bytea NOT NULL,
    entry_hash bytea NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL
);

ALTER TABLE public.audit_log ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.audit_log_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.audit_outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    event_type text NOT NULL,
    actor_user_id uuid,
    subject text DEFAULT ''::text NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL
);

ALTER TABLE public.audit_outbox ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.audit_outbox_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.auth_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL
);

CREATE TABLE public.ca_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    sealed bytea NOT NULL,
    public_material text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT ca_keys_kind_check CHECK ((kind = ANY (ARRAY['ssh'::text, 'x509'::text, 'mesh'::text])))
);

CREATE TABLE public.catalog_names (
    parent_id uuid,
    name text NOT NULL,
    folder_id uuid,
    asset_id uuid,
    CONSTRAINT canon_name CHECK ((name ~ '^[a-z0-9_-]+$'::text)),
    CONSTRAINT one_kind CHECK (((folder_id IS NOT NULL) <> (asset_id IS NOT NULL)))
);

CREATE TABLE public.folders (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    parent_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    path_ids ltree NOT NULL,
    CONSTRAINT folders_name_canon CHECK ((name ~ '^[a-z0-9_-]+$'::text)),
    CONSTRAINT no_self_parent CHECK ((parent_id IS DISTINCT FROM id))
);

CREATE TABLE public.group_memberships (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    member_user_id uuid,
    member_group_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT no_self_member CHECK ((member_group_id IS DISTINCT FROM group_id)),
    CONSTRAINT one_member CHECK (((member_user_id IS NOT NULL) <> (member_group_id IS NOT NULL)))
);

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    folder_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT groups_name_check CHECK ((name ~ '^[a-z0-9_-]+$'::text))
);

CREATE TABLE public.live_sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    worker_id text NOT NULL,
    grant_id uuid,
    protocol text NOT NULL,
    principals text[] NOT NULL,
    client_key_fp text NOT NULL,
    started_at timestamptz DEFAULT now() NOT NULL,
    terminate_requested_at timestamptz
);

CREATE TABLE public.request_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid NOT NULL,
    scope_folder_id uuid,
    scope_asset_id uuid,
    required_approvals integer DEFAULT 1 NOT NULL,
    approver_role_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    requester_role_id uuid,
    max_duration interval,
    name text,
    CONSTRAINT request_policies_required_approvals_check CHECK ((required_approvals >= 0)),
    CONSTRAINT request_policies_name_canon CHECK (((name IS NULL) OR (name ~ '^[a-z0-9_-]+$'::text))),
    CONSTRAINT scope_shape CHECK ((((scope_folder_id IS NULL) AND (scope_asset_id IS NULL)) OR ((scope_folder_id IS NOT NULL) <> (scope_asset_id IS NOT NULL))))
);

CREATE TABLE public.request_policy_subjects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid NOT NULL,
    subject_user_id uuid,
    subject_group_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    kind text NOT NULL,
    CONSTRAINT one_subject CHECK (((subject_user_id IS NOT NULL) <> (subject_group_id IS NOT NULL))),
    CONSTRAINT request_policy_subjects_kind_check CHECK ((kind = ANY (ARRAY['requester'::text, 'approver'::text])))
);

CREATE TABLE public.role_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid NOT NULL,
    scope_folder_id uuid,
    scope_asset_id uuid,
    subject_user_id uuid,
    subject_group_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT at_most_one_scope CHECK ((NOT ((scope_folder_id IS NOT NULL) AND (scope_asset_id IS NOT NULL)))),
    CONSTRAINT one_subject CHECK (((subject_user_id IS NOT NULL) <> (subject_group_id IS NOT NULL)))
);

CREATE TABLE public.role_capabilities (
    role_id uuid NOT NULL,
    scope text NOT NULL,
    action text NOT NULL,
    qualifier text NOT NULL
);

CREATE TABLE public.role_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_id uuid NOT NULL,
    source_role_id uuid NOT NULL,
    via text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT no_self_same_object CHECK ((NOT ((role_id = source_role_id) AND (via = 'same_object'::text)))),
    CONSTRAINT role_grants_via_check CHECK ((via = ANY (ARRAY['same_object'::text, 'parent'::text])))
);

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    folder_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT roles_name_check CHECK ((name ~ '^[a-z0-9_-]+$'::text))
);

CREATE TABLE public.session_recordings (
    session_id uuid NOT NULL,
    user_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    worker_id text NOT NULL,
    protocol text NOT NULL,
    format text NOT NULL,
    object_key text NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    sha256 text DEFAULT ''::text NOT NULL,
    status text NOT NULL,
    started_at timestamptz,
    ended_at timestamptz,
    created_at timestamptz DEFAULT now() NOT NULL,
    grant_id uuid
);

CREATE TABLE public.session_signing_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sealed bytea NOT NULL,
    public_key bytea NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    active boolean DEFAULT true NOT NULL
);

CREATE TABLE public.ssh_asset_config (
    asset_id uuid NOT NULL,
    target_address text DEFAULT ''::text NOT NULL,
    host_public_key text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.ssh_asset_login (
    asset_id uuid NOT NULL,
    login text NOT NULL,
    kind text NOT NULL,
    secret_id uuid,
    CONSTRAINT ssh_asset_login_kind_check CHECK ((kind = ANY (ARRAY['ca'::text, 'password'::text, 'key'::text]))),
    CONSTRAINT ssh_login_secret_present CHECK (((kind = 'ca'::text) OR (secret_id IS NOT NULL)))
);

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    password_hash text DEFAULT ''::text NOT NULL,
    deactivated_at timestamptz
);

CREATE TABLE public.worker_presence (
    worker_id text NOT NULL,
    last_seen_at timestamptz DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_request_id_key UNIQUE (request_id);

ALTER TABLE ONLY public.access_request_approvals
    ADD CONSTRAINT access_request_approvals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.access_request_approvals
    ADD CONSTRAINT access_request_approvals_request_id_approver_user_id_key UNIQUE (request_id, approver_user_id);

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.request_policy_subjects
    ADD CONSTRAINT request_policy_subjects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_secrets
    ADD CONSTRAINT asset_secrets_asset_id_name_key UNIQUE (asset_id, name);

ALTER TABLE ONLY public.asset_secrets
    ADD CONSTRAINT asset_secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_entry_hash_key UNIQUE (entry_hash);

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_seq_key UNIQUE (seq);

ALTER TABLE ONLY public.audit_outbox
    ADD CONSTRAINT audit_outbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.ca_keys
    ADD CONSTRAINT ca_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.group_memberships
    ADD CONSTRAINT group_memberships_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.live_sessions
    ADD CONSTRAINT live_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.role_capabilities
    ADD CONSTRAINT role_capabilities_pkey PRIMARY KEY (role_id, scope, action, qualifier);

ALTER TABLE ONLY public.role_grants
    ADD CONSTRAINT role_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.role_grants
    ADD CONSTRAINT role_grants_role_id_source_role_id_via_key UNIQUE (role_id, source_role_id, via);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.session_recordings
    ADD CONSTRAINT session_recordings_pkey PRIMARY KEY (session_id);

ALTER TABLE ONLY public.session_signing_keys
    ADD CONSTRAINT session_signing_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.ssh_asset_config
    ADD CONSTRAINT ssh_asset_config_pkey PRIMARY KEY (asset_id);

ALTER TABLE ONLY public.ssh_asset_login
    ADD CONSTRAINT ssh_asset_login_pkey PRIMARY KEY (asset_id, login);

ALTER TABLE ONLY public.asset_secrets
    ADD CONSTRAINT uq_asset_secret_asset_id UNIQUE (asset_id, id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.worker_presence
    ADD CONSTRAINT worker_presence_pkey PRIMARY KEY (worker_id);

CREATE INDEX idx_access_grants_active ON public.access_grants USING btree (subject_user_id) WHERE (revoked_at IS NULL);

CREATE INDEX idx_access_grants_granted_id ON public.access_grants USING btree (granted_at DESC, id);

CREATE INDEX idx_access_grants_role ON public.access_grants USING btree (role_id);

CREATE INDEX idx_access_requests_created_id ON public.access_requests USING btree (created_at DESC, id);

CREATE INDEX idx_access_requests_pending ON public.access_requests USING btree (created_at DESC) WHERE (status = 'pending'::text);

CREATE INDEX idx_access_requests_pending_asset ON public.access_requests USING btree (asset_id) WHERE (status = 'pending'::text);

CREATE INDEX idx_access_requests_pending_role ON public.access_requests USING btree (role_id) WHERE (status = 'pending'::text);

CREATE INDEX idx_access_requests_requester ON public.access_requests USING btree (requester_user_id);

CREATE INDEX idx_request_policy_subjects_policy ON public.request_policy_subjects USING btree (policy_id);

CREATE INDEX idx_asset_secrets_name_id ON public.asset_secrets USING btree (name, id);

CREATE INDEX idx_assets_folder ON public.assets USING btree (folder_id);

CREATE INDEX idx_assets_folder_name_id ON public.assets USING btree (folder_id, name, id);

CREATE INDEX idx_assets_labels ON public.assets USING gin (labels);

CREATE INDEX idx_assets_name_id ON public.assets USING btree (name, id);

CREATE INDEX idx_assets_name_trgm ON public.assets USING gin (name public.gin_trgm_ops);

CREATE INDEX idx_audit_outbox_seq ON public.audit_outbox USING btree (seq);

CREATE INDEX idx_audit_seq ON public.audit_log USING btree (seq);

CREATE INDEX idx_auth_tokens_user ON public.auth_tokens USING btree (user_id);

CREATE INDEX idx_catalog_names_asset ON public.catalog_names USING btree (asset_id) WHERE (asset_id IS NOT NULL);

CREATE INDEX idx_catalog_names_folder ON public.catalog_names USING btree (folder_id) WHERE (folder_id IS NOT NULL);

CREATE INDEX idx_folders_name_id ON public.folders USING btree (name, id);

CREATE INDEX idx_folders_name_trgm ON public.folders USING gin (name public.gin_trgm_ops);

CREATE INDEX idx_folders_parent ON public.folders USING btree (parent_id);

CREATE INDEX idx_folders_parent_name_id ON public.folders USING btree (parent_id, name, id);

CREATE INDEX idx_folders_path_ids ON public.folders USING gist (path_ids);

CREATE INDEX idx_gm_member_group ON public.group_memberships USING btree (member_group_id) WHERE (member_group_id IS NOT NULL);

CREATE INDEX idx_gm_member_user ON public.group_memberships USING btree (member_user_id) WHERE (member_user_id IS NOT NULL);

CREATE INDEX idx_group_memberships_created_id ON public.group_memberships USING btree (created_at DESC, id);

CREATE INDEX idx_groups_folder ON public.groups USING btree (folder_id) WHERE (folder_id IS NOT NULL);

CREATE INDEX idx_groups_name_id ON public.groups USING btree (name, id);

CREATE INDEX idx_groups_name_trgm ON public.groups USING gin (name public.gin_trgm_ops);

CREATE INDEX idx_live_sessions_grant ON public.live_sessions USING btree (grant_id);

CREATE INDEX idx_live_sessions_user_asset ON public.live_sessions USING btree (user_id, asset_id);

CREATE INDEX idx_live_sessions_worker ON public.live_sessions USING btree (worker_id);

CREATE INDEX idx_rb_role ON public.role_bindings USING btree (role_id);

CREATE INDEX idx_rb_scope_asset ON public.role_bindings USING btree (scope_asset_id) WHERE (scope_asset_id IS NOT NULL);

CREATE INDEX idx_rb_scope_folder ON public.role_bindings USING btree (scope_folder_id) WHERE (scope_folder_id IS NOT NULL);

CREATE INDEX idx_rb_subj_group ON public.role_bindings USING btree (subject_group_id) WHERE (subject_group_id IS NOT NULL);

CREATE INDEX idx_rb_subj_user ON public.role_bindings USING btree (subject_user_id) WHERE (subject_user_id IS NOT NULL);

CREATE INDEX idx_request_policies_created_id ON public.request_policies USING btree (created_at DESC, id);

CREATE INDEX idx_request_policy_subjects_created_id ON public.request_policy_subjects USING btree (created_at DESC, id);

CREATE INDEX idx_role_bindings_created_id ON public.role_bindings USING btree (created_at DESC, id);

CREATE INDEX idx_role_capabilities_match ON public.role_capabilities USING btree (scope, action, qualifier);

CREATE INDEX idx_role_grants_created_id ON public.role_grants USING btree (created_at DESC, id);

CREATE INDEX idx_role_grants_role ON public.role_grants USING btree (role_id);

CREATE INDEX idx_role_grants_source ON public.role_grants USING btree (source_role_id, via);

CREATE INDEX idx_roles_folder ON public.roles USING btree (folder_id) WHERE (folder_id IS NOT NULL);

CREATE INDEX idx_roles_name_id ON public.roles USING btree (name, id);

CREATE INDEX idx_roles_name_trgm ON public.roles USING gin (name public.gin_trgm_ops);

CREATE INDEX idx_session_recordings_created_id ON public.session_recordings USING btree (created_at DESC, session_id);

CREATE INDEX idx_users_email_id ON public.users USING btree (email, id);

CREATE INDEX session_recordings_asset_idx ON public.session_recordings USING btree (asset_id, created_at DESC);

CREATE INDEX session_recordings_grant_idx ON public.session_recordings USING btree (grant_id) WHERE (grant_id IS NOT NULL);

CREATE INDEX session_recordings_user_idx ON public.session_recordings USING btree (user_id, created_at DESC);

CREATE UNIQUE INDEX uq_active_ca ON public.ca_keys USING btree (kind) WHERE active;

CREATE UNIQUE INDEX uq_active_session_key ON public.session_signing_keys USING btree (active) WHERE active;

CREATE UNIQUE INDEX uq_group_name_folder ON public.groups USING btree (folder_id, name) WHERE (folder_id IS NOT NULL);

CREATE UNIQUE INDEX uq_group_name_global ON public.groups USING btree (name) WHERE (folder_id IS NULL);

CREATE UNIQUE INDEX uq_membership_group ON public.group_memberships USING btree (group_id, member_group_id) WHERE (member_group_id IS NOT NULL);

CREATE UNIQUE INDEX uq_membership_user ON public.group_memberships USING btree (group_id, member_user_id) WHERE (member_user_id IS NOT NULL);

CREATE UNIQUE INDEX uq_pending_request ON public.access_requests USING btree (requester_user_id, role_id, asset_id) WHERE (status = 'pending'::text);

CREATE UNIQUE INDEX uq_policy_name_asset ON public.request_policies USING btree (name, scope_asset_id) WHERE ((name IS NOT NULL) AND (scope_asset_id IS NOT NULL));

CREATE UNIQUE INDEX uq_policy_name_folder ON public.request_policies USING btree (name, scope_folder_id) WHERE ((name IS NOT NULL) AND (scope_folder_id IS NOT NULL));

CREATE UNIQUE INDEX uq_role_name_folder ON public.roles USING btree (folder_id, name) WHERE (folder_id IS NOT NULL);

CREATE UNIQUE INDEX uq_role_name_global ON public.roles USING btree (name) WHERE (folder_id IS NULL);

CREATE UNIQUE INDEX uq_request_policy_role_asset ON public.request_policies USING btree (role_id, scope_asset_id) WHERE (scope_asset_id IS NOT NULL);

CREATE UNIQUE INDEX uq_request_policy_role_default ON public.request_policies USING btree (role_id) WHERE ((scope_folder_id IS NULL) AND (scope_asset_id IS NULL));

CREATE UNIQUE INDEX uq_request_policy_role_folder ON public.request_policies USING btree (role_id, scope_folder_id) WHERE (scope_folder_id IS NOT NULL);

CREATE UNIQUE INDEX uq_sibling_child ON public.catalog_names USING btree (parent_id, name) WHERE (parent_id IS NOT NULL);

CREATE UNIQUE INDEX uq_sibling_root ON public.catalog_names USING btree (name) WHERE (parent_id IS NULL);

CREATE TRIGGER trg_folders_path_ins BEFORE INSERT ON public.folders FOR EACH ROW EXECUTE FUNCTION public.folders_set_path_ids();

CREATE TRIGGER trg_folders_path_move AFTER UPDATE OF parent_id ON public.folders FOR EACH ROW WHEN ((old.parent_id IS DISTINCT FROM new.parent_id)) EXECUTE FUNCTION public.folders_move_path_ids();

CREATE TRIGGER trg_group_memberships_authz AFTER DELETE ON public.group_memberships FOR EACH ROW EXECUTE FUNCTION public.notify_authz_changed_membership_delete();

CREATE TRIGGER trg_role_bindings_authz AFTER DELETE ON public.role_bindings FOR EACH ROW EXECUTE FUNCTION public.notify_authz_changed_binding_delete();

CREATE TRIGGER trg_role_grants_authz AFTER DELETE OR UPDATE ON public.role_grants FOR EACH STATEMENT EXECUTE FUNCTION public.notify_authz_changed();

CREATE TRIGGER trg_roles_authz AFTER UPDATE ON public.roles FOR EACH STATEMENT EXECUTE FUNCTION public.notify_authz_changed();

CREATE TRIGGER trg_users_authz AFTER UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.notify_authz_changed_user_update();

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.access_requests(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_scope_asset_id_fkey FOREIGN KEY (scope_asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_request_approvals
    ADD CONSTRAINT access_request_approvals_approver_user_id_fkey FOREIGN KEY (approver_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_request_approvals
    ADD CONSTRAINT access_request_approvals_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.access_requests(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_requester_user_id_fkey FOREIGN KEY (requester_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policy_subjects
    ADD CONSTRAINT request_policy_subjects_rule_id_fkey FOREIGN KEY (policy_id) REFERENCES public.request_policies(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policy_subjects
    ADD CONSTRAINT request_policy_subjects_subject_group_id_fkey FOREIGN KEY (subject_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policy_subjects
    ADD CONSTRAINT request_policy_subjects_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_approver_role_id_fkey FOREIGN KEY (approver_role_id) REFERENCES public.roles(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_scope_asset_id_fkey FOREIGN KEY (scope_asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_scope_folder_id_fkey FOREIGN KEY (scope_folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.asset_secrets
    ADD CONSTRAINT asset_secrets_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.catalog_names
    ADD CONSTRAINT catalog_names_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.catalog_names
    ADD CONSTRAINT catalog_names_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.catalog_names
    ADD CONSTRAINT catalog_names_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.group_memberships
    ADD CONSTRAINT group_memberships_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.group_memberships
    ADD CONSTRAINT group_memberships_member_group_id_fkey FOREIGN KEY (member_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.group_memberships
    ADD CONSTRAINT group_memberships_member_user_id_fkey FOREIGN KEY (member_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.live_sessions
    ADD CONSTRAINT live_sessions_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.live_sessions
    ADD CONSTRAINT live_sessions_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES public.access_grants(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.live_sessions
    ADD CONSTRAINT live_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.request_policies
    ADD CONSTRAINT request_policies_requester_role_id_fkey FOREIGN KEY (requester_role_id) REFERENCES public.roles(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_scope_asset_id_fkey FOREIGN KEY (scope_asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_scope_folder_id_fkey FOREIGN KEY (scope_folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_subject_group_id_fkey FOREIGN KEY (subject_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_bindings
    ADD CONSTRAINT role_bindings_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_capabilities
    ADD CONSTRAINT role_capabilities_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_grants
    ADD CONSTRAINT role_grants_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_grants
    ADD CONSTRAINT role_grants_source_role_id_fkey FOREIGN KEY (source_role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_folder_id_fkey FOREIGN KEY (folder_id) REFERENCES public.folders(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.session_recordings
    ADD CONSTRAINT session_recordings_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES public.access_grants(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.ssh_asset_config
    ADD CONSTRAINT ssh_asset_config_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ssh_asset_login
    ADD CONSTRAINT ssh_asset_login_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.ssh_asset_login
    ADD CONSTRAINT ssh_login_secret_same_asset FOREIGN KEY (asset_id, secret_id) REFERENCES public.asset_secrets(asset_id, id) ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose StatementBegin
-- active_access_grants: the single source of the "grant is live" predicate.
-- Shared by authz_held_impl (grant arm) and authz_role_goals (grant satisfaction),
-- replacing the hand-copied `revoked_at IS NULL AND expires_at > now()` arms.
CREATE VIEW active_access_grants AS
    SELECT * FROM access_grants
    WHERE revoked_at IS NULL AND expires_at > now();
-- +goose StatementEnd

-- +goose StatementBegin
-- authz_user_is_active: the deactivation guard for the request_policy_subjects
-- arms that bypass the held closure. STABLE so it inlines in EXISTS predicates.
CREATE FUNCTION authz_user_is_active(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM users u WHERE u.id = p_user AND u.deactivated_at IS NULL)
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS
    access_request_approvals, live_sessions, session_recordings, ssh_asset_login,
    role_capabilities, request_policy_subjects, access_grants, access_requests,
    request_policies, role_bindings, role_grants, catalog_names, ssh_asset_config,
    asset_secrets, auth_tokens, audit_log, audit_outbox, session_signing_keys,
    worker_presence, groups, assets, roles, folders, ca_keys, users CASCADE;
DROP FUNCTION IF EXISTS notify_authz_changed(), notify_authz_changed_user_update(),
    notify_authz_changed_membership_delete(), notify_authz_changed_binding_delete(),
    folders_set_path_ids(), folders_move_path_ids();
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS ltree;
DROP EXTENSION IF EXISTS pgcrypto;
-- +goose StatementEnd
