package apiguard

import (
	"context"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// RoleCapsByRoleIDs batches the per-role capability lookup that RoleCapsStrings does
// one role at a time: a single query for a set of roles, returning role_id → the
// reconstructed capability pattern strings. Reconstruction (authz.ReconstructCap) and
// the per-role slice order (query row order) match RoleCapsStrings. A role with no
// capabilities has no map entry (lookup yields a nil slice).
func RoleCapsByRoleIDs(ctx context.Context, q *sqlc.Queries, ids []uuid.UUID) (map[uuid.UUID][]string, error) {
	rows, err := q.RoleCapabilitiesByRoleIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]string, len(ids))
	for _, r := range rows {
		out[r.RoleID] = append(out[r.RoleID], authz.ReconstructCap(r.Scope, r.Action, r.Qualifier))
	}
	return out, nil
}
