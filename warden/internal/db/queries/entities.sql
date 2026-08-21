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

-- name: RemoveUserFromGroup :exec
DELETE FROM group_memberships WHERE group_id = $1 AND member_user_id = $2;

-- name: RemoveGroupFromGroup :exec
DELETE FROM group_memberships WHERE group_id = $1 AND member_group_id = $2;

-- name: ListGroupMemberUsers :many
SELECT u.* FROM users u
JOIN group_memberships gm ON gm.member_user_id = u.id
WHERE gm.group_id = $1
ORDER BY u.id;

-- name: ListGroupMemberGroups :many
SELECT g.* FROM groups g
JOIN group_memberships gm ON gm.member_group_id = g.id
WHERE gm.group_id = $1
ORDER BY g.id;

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
INSERT INTO roles (name, folder_id, capabilities) VALUES ($1, $2, $3) RETURNING *;

-- name: CreateRoleBinding :one
INSERT INTO role_bindings
  (role_id, scope_folder_id, scope_asset_id, subject_user_id, subject_group_id)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users
WHERE ($1::uuid IS NULL OR id > $1)
ORDER BY id
LIMIT $2;

-- name: CreateUserFull :one
INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING *;

-- name: ListGroupsPaged :many
SELECT * FROM groups
WHERE ($1::uuid IS NULL OR id > $1)
ORDER BY id
LIMIT $2;
