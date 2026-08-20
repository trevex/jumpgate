-- +goose Up
-- Sibling-name uniqueness for the catalog tree. catalog_names is the single source
-- of truth: every folder and asset owns exactly one row keyed by (containing folder,
-- name). One partial UNIQUE index over (parent_id, name) makes folder<->folder,
-- asset<->asset, AND folder<->asset collisions a plain unique violation, race-free
-- under READ COMMITTED with no trigger. parent_id NULL = a top-level folder (assets
-- are never top-level). Names are restricted to a principal-safe, dot-free charset so
-- the '.'-joined path parses unambiguously; a rename/move endpoint would invalidate
-- derived principals and MUST NOT be added without revisiting this.
ALTER TABLE folders ADD CONSTRAINT folders_name_canon CHECK (name ~ '^[a-z0-9_-]+$');
ALTER TABLE assets  ADD CONSTRAINT assets_name_canon  CHECK (name ~ '^[a-z0-9_-]+$');

CREATE TABLE catalog_names (
    parent_id uuid REFERENCES folders(id) ON DELETE CASCADE,
    name      text NOT NULL,
    folder_id uuid REFERENCES folders(id) ON DELETE CASCADE,
    asset_id  uuid REFERENCES assets(id)  ON DELETE CASCADE,
    CONSTRAINT one_kind   CHECK ((folder_id IS NOT NULL) <> (asset_id IS NOT NULL)),
    CONSTRAINT canon_name CHECK (name ~ '^[a-z0-9_-]+$')
);
CREATE UNIQUE INDEX uq_sibling_child ON catalog_names(parent_id, name) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX uq_sibling_root  ON catalog_names(name)            WHERE parent_id IS NULL;

-- Backfill existing rows. If any pre-existing name violates the charset or a pair of
-- siblings collide, this migration fails loudly rather than silently dropping data.
INSERT INTO catalog_names (parent_id, name, folder_id)
SELECT parent_id, name, id FROM folders;
INSERT INTO catalog_names (parent_id, name, asset_id)
SELECT folder_id, name, id FROM assets;

-- +goose Down
DROP TABLE catalog_names;
ALTER TABLE assets  DROP CONSTRAINT assets_name_canon;
ALTER TABLE folders DROP CONSTRAINT folders_name_canon;
