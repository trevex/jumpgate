package rpc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// createRoleWithCaps creates a role and populates its capabilities from a JSON
// capability array string (e.g. `["ssh:login:deploy","**"]`). It returns the
// new role. Tests that previously called q.CreateRole with a Capabilities field
// should use this instead.
func createRoleWithCaps(t *testing.T, ctx context.Context, q *sqlc.Queries, name string, folderID pgtype.UUID, capsJSON string) sqlc.Role { //nolint:revive
	t.Helper()
	role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: name, FolderID: folderID})
	if err != nil {
		t.Fatalf("createRoleWithCaps: create role %q: %v", name, err)
	}
	var patterns []string
	if err := json.Unmarshal([]byte(capsJSON), &patterns); err != nil {
		t.Fatalf("createRoleWithCaps: unmarshal caps %q: %v", capsJSON, err)
	}
	for _, pat := range patterns {
		sc, ac, qu := authz.NormalizeCap(pat)
		if err := q.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{
			RoleID:    role.ID,
			Scope:     sc,
			Action:    ac,
			Qualifier: qu,
		}); err != nil {
			t.Fatalf("createRoleWithCaps: insert cap %q for role %q: %v", pat, name, err)
		}
	}
	return role
}
