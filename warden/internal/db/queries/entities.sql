-- name: CreateUser :one
INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING *;

-- name: CreateGroup :one
INSERT INTO groups (name) VALUES ($1) RETURNING *;

-- name: AddUserToGroup :exec
INSERT INTO group_memberships (group_id, member_user_id) VALUES ($1, $2);

-- name: AddGroupToGroup :exec
INSERT INTO group_memberships (group_id, member_group_id) VALUES ($1, $2);

-- name: CreateFolder :one
INSERT INTO folders (name, parent_id) VALUES ($1, $2) RETURNING *;

-- name: CreateAsset :one
INSERT INTO assets (folder_id, name, labels) VALUES ($1, $2, $3) RETURNING *;

-- name: CreateRole :one
INSERT INTO roles (name, resource_type, capabilities) VALUES ($1, $2, $3) RETURNING *;

-- name: CreateRoleBinding :one
INSERT INTO role_bindings
  (role_id, kind, scope_folder_id, scope_asset_id, subject_user_id, subject_group_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAsset :one
SELECT * FROM assets WHERE id = $1;
