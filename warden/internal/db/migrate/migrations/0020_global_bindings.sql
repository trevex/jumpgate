-- +goose Up
-- Allow scopeless (global) standing bindings: a role_binding with both
-- scope_folder_id and scope_asset_id NULL confers the role tenant-wide. The
-- original one_scope CHECK required EXACTLY one scope; relax it to AT MOST one so
-- global management capabilities (governed at ScopeGlobal) can be bound. Scoped
-- bindings are unaffected: they still set exactly one of folder/asset.
ALTER TABLE role_bindings DROP CONSTRAINT one_scope;
ALTER TABLE role_bindings ADD CONSTRAINT at_most_one_scope CHECK (
    NOT (scope_folder_id IS NOT NULL AND scope_asset_id IS NOT NULL)
);

-- +goose Down
-- Drop any global bindings before reinstating the exactly-one constraint, else the
-- restore would fail on rows the old constraint forbids.
DELETE FROM role_bindings WHERE scope_folder_id IS NULL AND scope_asset_id IS NULL;
ALTER TABLE role_bindings DROP CONSTRAINT at_most_one_scope;
ALTER TABLE role_bindings ADD CONSTRAINT one_scope CHECK (
    (scope_folder_id IS NOT NULL) <> (scope_asset_id IS NOT NULL)
);
