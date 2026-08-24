-- +goose Up
-- Catalog search (the ⌘K palette / SearchCatalog) matches slug-like names by
-- substring. A B-tree cannot serve `name ILIKE '%q%'`; pg_trgm's GIN trigram index
-- can, turning the whole-catalog scan + in-process substring filter into an indexed
-- lookup that returns only the few name matches.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX idx_folders_name_trgm ON folders USING gin (name gin_trgm_ops);
CREATE INDEX idx_assets_name_trgm  ON assets  USING gin (name gin_trgm_ops);
CREATE INDEX idx_roles_name_trgm   ON roles   USING gin (name gin_trgm_ops);
CREATE INDEX idx_groups_name_trgm  ON groups  USING gin (name gin_trgm_ops);

-- +goose Down
DROP INDEX IF EXISTS idx_groups_name_trgm;
DROP INDEX IF EXISTS idx_roles_name_trgm;
DROP INDEX IF EXISTS idx_assets_name_trgm;
DROP INDEX IF EXISTS idx_folders_name_trgm;
DROP EXTENSION IF EXISTS pg_trgm;
