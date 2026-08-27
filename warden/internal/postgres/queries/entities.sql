-- name: CreateUser :one
INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING *;

-- name: CreateGroup :one
INSERT INTO groups (name, folder_id) VALUES ($1, $2) RETURNING *;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = $1;

-- name: GetGroupByNameGlobal :one
SELECT * FROM groups WHERE name = $1 AND folder_id IS NULL;

-- name: GetGroupByFolderAndName :one
SELECT * FROM groups WHERE folder_id = $1 AND name = $2;

-- name: AddUserToGroup :exec
INSERT INTO group_memberships (group_id, member_user_id) VALUES ($1, $2);

-- name: AddGroupToGroup :exec
INSERT INTO group_memberships (group_id, member_group_id) VALUES ($1, $2);

-- name: GroupNestingCyclic :one
-- AddGroupToGroup cycle check: whether making member_group_id a member of group_id
-- would close a cycle — true iff group_id is ALREADY a transitive supergroup of
-- member_group_id (walking member->super edges up from group_id).
WITH RECURSIVE supergroups(gid) AS (
    SELECT group_id FROM group_memberships WHERE member_group_id = sqlc.arg('group_id')
  UNION
    SELECT gm.group_id FROM group_memberships gm JOIN supergroups sg ON gm.member_group_id = sg.gid
)
SELECT EXISTS (SELECT 1 FROM supergroups WHERE gid = sqlc.arg('member_group_id'));

-- name: RemoveUserFromGroup :exec
DELETE FROM group_memberships WHERE group_id = $1 AND member_user_id = $2;

-- name: RemoveGroupFromGroup :exec
DELETE FROM group_memberships WHERE group_id = $1 AND member_group_id = $2;

-- name: ListGroupMembersPaged :many
-- Single keyset scan over group_memberships ordered by (created_at DESC, id).
-- Each row is either a user-member (member_user_id non-null) or group-member
-- (member_group_id non-null); the handler splits them.
SELECT gm.* FROM group_memberships gm
WHERE gm.group_id = sqlc.arg('group_id')
  AND (
    sqlc.narg('after_ts')::timestamptz IS NULL
    OR gm.created_at < sqlc.narg('after_ts')
    OR (gm.created_at = sqlc.narg('after_ts') AND gm.id > sqlc.narg('after_id')::uuid)
  )
ORDER BY gm.created_at DESC, gm.id
LIMIT sqlc.arg('lim');

-- name: DeactivateUser :exec
UPDATE users SET deactivated_at = now() WHERE id = $1 AND deactivated_at IS NULL;

-- name: ReactivateUser :exec
UPDATE users SET deactivated_at = NULL WHERE id = $1;

-- name: DeleteGroup :exec
DELETE FROM groups WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: CreateFolder :one
INSERT INTO folders (name, parent_id) VALUES ($1, $2) RETURNING *;

-- name: CreateAsset :one
INSERT INTO assets (folder_id, name, labels, kind) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: InsertFolderName :exec
INSERT INTO catalog_names (parent_id, name, folder_id) VALUES ($1, $2, $3);

-- name: InsertAssetName :exec
INSERT INTO catalog_names (parent_id, name, asset_id) VALUES ($1, $2, $3);

-- name: CreateRole :one
INSERT INTO roles (name, folder_id) VALUES ($1, $2) RETURNING *;

-- name: InsertRoleCapability :exec
INSERT INTO role_capabilities (role_id, scope, action, qualifier) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING;

-- name: RoleCapabilityRows :many
SELECT scope, action, qualifier FROM role_capabilities WHERE role_id = $1;

-- name: DeleteRole :exec
-- Deletes the role row. The role's name uniqueness is enforced by the partial
-- UNIQUE indexes on roles(name)/roles(folder_id, name), so deleting the row frees
-- the name automatically (no separate registry entry). Final step of DeleteRole,
-- run only after its bindings/edges/policies are removed and its grants revoked.
DELETE FROM roles WHERE id = $1;

-- name: CreateRoleBinding :one
INSERT INTO role_bindings
  (role_id, scope_folder_id, scope_asset_id, subject_user_id, subject_group_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users
WHERE (
  sqlc.narg('after_email')::text IS NULL
  OR (email, id) > (sqlc.narg('after_email'), sqlc.narg('after_id')::uuid)
)
ORDER BY email, id
LIMIT sqlc.arg('lim');

-- name: CreateUserFull :one
INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING *;

-- name: ListGroupsPaged :many
SELECT * FROM groups
WHERE (
  sqlc.narg('after_name')::text IS NULL
  OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
)
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: ListGroupsByIDsPaged :many
SELECT * FROM groups
WHERE id = ANY($1::uuid[])
  AND (
    sqlc.narg('after_name')::text IS NULL
    OR (name, id) > (sqlc.narg('after_name'), sqlc.narg('after_id')::uuid)
  )
ORDER BY name, id
LIMIT sqlc.arg('lim');

-- name: CountChildFolders :one
SELECT count(*) FROM folders WHERE parent_id = $1;

-- name: CountAssetsInFolder :one
SELECT count(*) FROM assets WHERE folder_id = $1;

-- name: CountRolesHomedInFolder :one
SELECT count(*) FROM roles WHERE folder_id = $1;

-- name: CountGroupsHomedInFolder :one
SELECT count(*) FROM groups WHERE folder_id = $1;

-- name: CountBindingsScopedToFolder :one
SELECT count(*) FROM role_bindings WHERE scope_folder_id = $1;

-- name: CountPoliciesScopedToFolder :one
SELECT count(*) FROM request_policies WHERE scope_folder_id = $1;

-- name: DeleteFolder :exec
DELETE FROM folders WHERE id = $1;

-- name: UpdateFolderName :exec
UPDATE folders SET name = $2 WHERE id = $1;

-- name: UpdateFolderParent :exec
UPDATE folders SET parent_id = $2 WHERE id = $1;

-- name: UpdateAssetName :exec
UPDATE assets SET name = $2 WHERE id = $1;

-- name: UpdateAssetFolder :exec
UPDATE assets SET folder_id = $2 WHERE id = $1;

-- name: UpdateFolderCatalogName :exec
UPDATE catalog_names SET parent_id = $2, name = $3 WHERE folder_id = $1;

-- name: UpdateAssetCatalogName :exec
UPDATE catalog_names SET parent_id = $2, name = $3 WHERE asset_id = $1;

-- name: NotifyAuthzChanged :exec
SELECT pg_notify('authz_changed', '');

-- name: CountGroupMembers :one
-- Direct membership count for a group (users + nested groups), for roster/badge display.
SELECT count(*)::int FROM group_memberships WHERE group_id = $1;
