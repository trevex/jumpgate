package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sqlAuthorizer resolves access with recursive SQL over the control-plane Postgres.
type sqlAuthorizer struct {
	pool *pgxpool.Pool
}

// NewSQLAuthorizer returns an Authorizer backed by Postgres.
func NewSQLAuthorizer(pool *pgxpool.Pool) Authorizer {
	return &sqlAuthorizer{pool: pool}
}

// applicableCTE computes, for a user ($1), every asset reachable via an applicable
// binding, tagged with the binding kind and role. It expands transitive group
// membership, folder-subtree inheritance, and both asset- and folder-scoped
// bindings for user- or (nested) group-subjects.
const applicableCTE = `
WITH RECURSIVE user_groups(group_id) AS (
    SELECT group_id FROM group_memberships WHERE member_user_id = $1
  UNION
    SELECT gm.group_id
    FROM group_memberships gm
    JOIN user_groups ug ON gm.member_group_id = ug.group_id
),
folder_tree(root_id, folder_id) AS (
    SELECT id, id FROM folders
  UNION
    SELECT ft.root_id, f.id
    FROM folders f JOIN folder_tree ft ON f.parent_id = ft.folder_id
),
applicable(asset_id, kind, role_id) AS (
    SELECT rb.scope_asset_id, rb.kind, rb.role_id
    FROM role_bindings rb
    WHERE rb.scope_asset_id IS NOT NULL
      AND ( rb.subject_user_id = $1
            OR rb.subject_group_id IN (SELECT group_id FROM user_groups) )
  UNION ALL
    SELECT a.id, rb.kind, rb.role_id
    FROM role_bindings rb
    JOIN folder_tree ft ON ft.root_id = rb.scope_folder_id
    JOIN assets a ON a.folder_id = ft.folder_id
    WHERE rb.scope_folder_id IS NOT NULL
      AND ( rb.subject_user_id = $1
            OR rb.subject_group_id IN (SELECT group_id FROM user_groups) )
)`

func (s *sqlAuthorizer) VisibleAssets(ctx context.Context, userID uuid.UUID) ([]AssetVisibility, error) {
	rows, err := s.pool.Query(ctx, applicableCTE+`
SELECT asset_id, kind, role_id FROM applicable`, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets: %w", err)
	}
	defer rows.Close()

	type acc struct {
		active bool
		seen   map[uuid.UUID]struct{}
		roles  []uuid.UUID
	}
	byAsset := map[uuid.UUID]*acc{}
	var order []uuid.UUID
	for rows.Next() {
		var assetID, roleID uuid.UUID
		var kind string
		if err := rows.Scan(&assetID, &kind, &roleID); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		a := byAsset[assetID]
		if a == nil {
			a = &acc{seen: map[uuid.UUID]struct{}{}}
			byAsset[assetID] = a
			order = append(order, assetID)
		}
		if kind == "standing" {
			a.active = true
		}
		if _, ok := a.seen[roleID]; !ok {
			a.seen[roleID] = struct{}{}
			a.roles = append(a.roles, roleID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]AssetVisibility, 0, len(order))
	for _, id := range order {
		a := byAsset[id]
		out = append(out, AssetVisibility{AssetID: id, Active: a.active, RoleIDs: a.roles})
	}
	return out, nil
}

func (s *sqlAuthorizer) RolesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (AssetRoles, error) {
	rows, err := s.pool.Query(ctx, applicableCTE+`
SELECT kind, role_id FROM applicable WHERE asset_id = $2`, userID, assetID)
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset: %w", err)
	}
	defer rows.Close()

	activeSeen := map[uuid.UUID]struct{}{}
	reqSeen := map[uuid.UUID]struct{}{}
	var r AssetRoles
	for rows.Next() {
		var kind string
		var roleID uuid.UUID
		if err := rows.Scan(&kind, &roleID); err != nil {
			return AssetRoles{}, fmt.Errorf("scan: %w", err)
		}
		switch kind {
		case "standing":
			if _, ok := activeSeen[roleID]; !ok {
				activeSeen[roleID] = struct{}{}
				r.Active = append(r.Active, roleID)
			}
		case "requestable":
			if _, ok := reqSeen[roleID]; !ok {
				reqSeen[roleID] = struct{}{}
				r.Requestable = append(r.Requestable, roleID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return AssetRoles{}, err
	}
	return r, nil
}

func (s *sqlAuthorizer) Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, applicableCTE+`
SELECT EXISTS (
    SELECT 1
    FROM applicable ap
    JOIN roles r ON r.id = ap.role_id
    WHERE ap.asset_id = $2
      AND ap.kind = 'standing'
      AND jsonb_exists(r.capabilities, $3)
)`, userID, assetID, capability).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check: %w", err)
	}
	return ok, nil
}
