-- +goose Up
CREATE EXTENSION IF NOT EXISTS ltree;

-- Structural ID-path: the chain of ancestor folder ids (uuid hex, hyphens
-- stripped -> legal ltree labels) from root to self, inclusive. Rename-immune
-- (only moves change it); distinct from the display path in catalog_names.
ALTER TABLE folders ADD COLUMN path_ids ltree;

-- Backfill existing rows from the roots down.
WITH RECURSIVE t AS (
    SELECT id, replace(id::text, '-', '')::ltree AS p
    FROM folders WHERE parent_id IS NULL
  UNION ALL
    SELECT f.id, t.p || replace(f.id::text, '-', '')
    FROM folders f JOIN t ON f.parent_id = t.id
)
UPDATE folders f SET path_ids = t.p FROM t WHERE f.id = t.id;

ALTER TABLE folders ALTER COLUMN path_ids SET NOT NULL;
CREATE INDEX idx_folders_path_ids ON folders USING GIST (path_ids);

-- BEFORE INSERT: derive path_ids from the parent (or self for a root). NEW.id
-- already carries its default here, so the label is available.
-- +goose StatementBegin
CREATE FUNCTION folders_set_path_ids() RETURNS trigger AS $$
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
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER trg_folders_path_ins BEFORE INSERT ON folders
    FOR EACH ROW EXECUTE FUNCTION folders_set_path_ids();

-- AFTER UPDATE OF parent_id: re-root the moved subtree. Swaps the old prefix
-- (OLD.path_ids) for the node's new path across itself + all descendants. This
-- writes path_ids only (never parent_id) so it does not re-fire this trigger.
-- +goose StatementBegin
CREATE FUNCTION folders_move_path_ids() RETURNS trigger AS $$
DECLARE new_self ltree; parent_path ltree;
BEGIN
    IF NEW.parent_id IS NULL THEN
        new_self := replace(NEW.id::text, '-', '')::ltree;
    ELSE
        SELECT path_ids INTO parent_path FROM folders WHERE id = NEW.parent_id;
        new_self := parent_path || replace(NEW.id::text, '-', '');
    END IF;
    UPDATE folders
       SET path_ids = new_self || subpath(path_ids, nlevel(OLD.path_ids))
     WHERE path_ids <@ OLD.path_ids;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER trg_folders_path_move AFTER UPDATE OF parent_id ON folders
    FOR EACH ROW WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id)
    EXECUTE FUNCTION folders_move_path_ids();

-- +goose Down
DROP TRIGGER IF EXISTS trg_folders_path_move ON folders;
DROP TRIGGER IF EXISTS trg_folders_path_ins ON folders;
DROP FUNCTION IF EXISTS folders_move_path_ids();
DROP FUNCTION IF EXISTS folders_set_path_ids();
DROP INDEX IF EXISTS idx_folders_path_ids;
ALTER TABLE folders DROP COLUMN path_ids;
