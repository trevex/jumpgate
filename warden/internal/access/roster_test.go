package access_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestGetPolicyRoster proves the roster unions explicit subjects with standing
// role-holders and returns group nodes with resolved names + source.
func TestGetPolicyRoster(t *testing.T) {
	f := setupCascade(t)
	ctx, q := f.ctx, f.q

	grantRole := uuid.MustParse(f.createRole(t, "db-reader"))
	reqRole := uuid.MustParse(f.createRole(t, "eng-oncall"))

	p, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: grantRole, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequesterRoleID:   pgtype.UUID{Bytes: reqRole, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "roster-pol", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "oncall-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: reqRole, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		SubjectGroupID: pgtype.UUID{Bytes: grp.ID, Valid: true},
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	resp, err := f.acc.GetPolicyRoster(ctx, withToken(connect.NewRequest(&accessv1.GetPolicyRosterRequest{
		PolicyId: p.ID.String(),
	}), f.admin))
	if err != nil {
		t.Fatalf("GetPolicyRoster: %v", err)
	}
	var node *accessv1.RosterNode
	for _, n := range resp.Msg.Requesters {
		if n.SubjectId == grp.ID.String() {
			node = n
		}
	}
	if node == nil {
		t.Fatalf("group not in requester roster: %+v", resp.Msg.Requesters)
	}
	if node.Source != "via_role" || node.SubjectKind != "group" || node.DisplayName != grp.Name {
		t.Fatalf("bad node: %+v", node)
	}
}
