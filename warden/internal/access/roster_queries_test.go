package access_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestRoleStandingHoldersAndPolicyUsage proves the two new reads: a user bound to a
// role on the asset shows up as a standing holder of that role on the asset, and a
// role used as a policy's requestable + requester-source appears once per usage.
func TestRoleStandingHoldersAndPolicyUsage(t *testing.T) {
	f := setupCascade(t)
	ctx, q := f.ctx, f.q

	roleID := uuid.MustParse(f.createRole(t, "db-reader"))

	// Bind a fresh user to the role directly on the asset.
	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{
		Email: "holder-" + uuid.NewString()[:8] + "@test", DisplayName: "Holder",
	})
	if err != nil {
		t.Fatalf("CreateUserFull: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        roleID,
		ScopeAssetID:  pgtype.UUID{Bytes: f.asset, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	holders, err := q.RoleStandingHolders(ctx, sqlc.RoleStandingHoldersParams{
		RoleID: roleID, ObjectKind: "asset", ObjectID: f.asset,
	})
	if err != nil {
		t.Fatalf("RoleStandingHolders: %v", err)
	}
	found := false
	for _, h := range holders {
		if h.SubjectUserID.Valid && h.SubjectUserID.Bytes == u.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected user %s among standing holders, got %+v", u.ID, holders)
	}

	// Role used as requestable + requester-source on two policies.
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: roleID, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "req-on-asset", Valid: true},
	}); err != nil {
		t.Fatalf("CreateRequestPolicy requestable: %v", err)
	}
	other := uuid.MustParse(f.createRole(t, "db-writer"))
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: other, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequesterRoleID:   pgtype.UUID{Bytes: roleID, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "writer-req-src", Valid: true},
	}); err != nil {
		t.Fatalf("CreateRequestPolicy requester-source: %v", err)
	}

	usages, err := q.ListPoliciesUsingRole(ctx, roleID)
	if err != nil {
		t.Fatalf("ListPoliciesUsingRole: %v", err)
	}
	seen := map[string]bool{}
	for _, row := range usages {
		seen[row.Usage] = true
	}
	if !seen["requestable"] || !seen["requester_source"] {
		t.Fatalf("expected requestable + requester_source usages, got %+v", seen)
	}
}
