package access_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestListPoliciesUsingRole proves a role appears tagged as both requestable and
// approver_source across two policies.
func TestListPoliciesUsingRole(t *testing.T) {
	f := setupCascade(t)
	ctx, q := f.ctx, f.q

	role := uuid.MustParse(f.createRole(t, "db-admin"))
	other := uuid.MustParse(f.createRole(t, "db-reader"))

	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: role, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "admin-req", Valid: true},
	}); err != nil {
		t.Fatalf("CreateRequestPolicy requestable: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: other, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		ApproverRoleID:    pgtype.UUID{Bytes: role, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "reader-appr", Valid: true},
	}); err != nil {
		t.Fatalf("CreateRequestPolicy approver-source: %v", err)
	}

	resp, err := f.acc.ListPoliciesUsingRole(ctx, withToken(connect.NewRequest(&accessv1.ListPoliciesUsingRoleRequest{
		RoleId: role.String(),
	}), f.admin))
	if err != nil {
		t.Fatalf("ListPoliciesUsingRole: %v", err)
	}
	usages := map[string]bool{}
	for _, u := range resp.Msg.Usages {
		usages[u.Usage] = true
	}
	if !usages["requestable"] || !usages["approver_source"] {
		t.Fatalf("expected requestable+approver_source, got %+v", usages)
	}
}
