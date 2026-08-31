-- +goose Up
-- +goose StatementBegin
-- authz_mgmt_read_anchor_folders: folder ids the user directly holds a management
-- READ cap on — either the object's own read cap (p_scope/p_action/p_qual) OR the
-- subtree-wide catalog:folder:read broadening (authz.FolderReadCap). The single SQL
-- home of the read-broadening arm previously inlined in every Visible*Under query.
CREATE FUNCTION authz_mgmt_read_anchor_folders(p_user uuid, p_scope text, p_action text, p_qual text)
RETURNS TABLE(folder_id uuid)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT h.object_id
    FROM authz_held(p_user) h JOIN role_capabilities rc ON rc.role_id = h.role_id
    WHERE h.object_kind = 'folder'
      AND (
            ((rc.scope = p_scope OR rc.scope = '*') AND (rc.action = p_action OR rc.action = '*') AND (rc.qualifier = p_qual OR rc.qualifier = '*'))
         OR ((rc.scope = 'catalog' OR rc.scope = '*') AND (rc.action = 'folder' OR rc.action = '*') AND (rc.qualifier = 'read' OR rc.qualifier = '*'))
      )
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- authz_mgmt_visible_folders: the anchor folders cascaded DOWN their subtree (ltree
-- <@). These are the folders whose homed objects the user may see via management read.
CREATE FUNCTION authz_mgmt_visible_folders(p_user uuid, p_scope text, p_action text, p_qual text)
RETURNS TABLE(folder_id uuid)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT nf.id
    FROM authz_mgmt_read_anchor_folders(p_user, p_scope, p_action, p_qual) m
    JOIN folders mf ON mf.id = m.folder_id
    JOIN folders nf ON nf.path_ids <@ mf.path_ids
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- authz_mgmt_global_read: whether the user holds the object read cap OR
-- catalog:folder:read at global (scopeless) scope — the global_mgmt arm.
CREATE FUNCTION authz_mgmt_global_read(p_user uuid, p_scope text, p_action text, p_qual text)
RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM authz_global_held(p_user) gh JOIN role_capabilities rc ON rc.role_id = gh.role_id
        WHERE (
                ((rc.scope = p_scope OR rc.scope = '*') AND (rc.action = p_action OR rc.action = '*') AND (rc.qualifier = p_qual OR rc.qualifier = '*'))
             OR ((rc.scope = 'catalog' OR rc.scope = '*') AND (rc.action = 'folder' OR rc.action = '*') AND (rc.qualifier = 'read' OR rc.qualifier = '*'))
          )
    )
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS authz_mgmt_global_read(uuid, text, text, text);
DROP FUNCTION IF EXISTS authz_mgmt_visible_folders(uuid, text, text, text);
DROP FUNCTION IF EXISTS authz_mgmt_read_anchor_folders(uuid, text, text, text);
-- +goose StatementEnd
