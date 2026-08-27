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

// TestGetPolicyRosterGraduatedGate proves the graduated read gate: a caller holding
// access:policy:read (but not access:binding:read) at the policy scope sees the
// explicit subjects only — the role-derived standing holders stay hidden.
func TestGetPolicyRosterGraduatedGate(t *testing.T) {
	f := setupCascade(t)
	ctx, q := f.ctx, f.q

	grantRole := uuid.MustParse(f.createRole(t, "db-reader"))
	reqRole := uuid.MustParse(f.createRole(t, "eng-oncall"))

	p, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: grantRole, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequesterRoleID:   pgtype.UUID{Bytes: reqRole, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "grad-pol", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	// Explicit requester subject (a group named directly on the policy).
	explicit, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "explicit-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup explicit: %v", err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID: p.ID, Kind: "requester",
		SubjectGroupID: pgtype.UUID{Bytes: explicit.ID, Valid: true},
	}); err != nil {
		t.Fatalf("AddPolicySubject: %v", err)
	}

	// Role-derived standing holder (a group bound to the requester role on the asset).
	viaGrp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "via-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup via: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: reqRole, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		SubjectGroupID: pgtype.UUID{Bytes: viaGrp.ID, Valid: true},
	}); err != nil {
		t.Fatalf("CreateRoleBinding via: %v", err)
	}

	// Caller with access:policy:read on the asset, but NOT access:binding:read.
	seedCapUserScoped(t, f.pool, "policyreader@x", "pw123456", `["access:policy:read"]`, uuid.Nil, f.asset)
	tok := authClient(t, f.url, "policyreader@x", "pw123456")

	resp, err := f.acc.GetPolicyRoster(ctx, withToken(connect.NewRequest(&accessv1.GetPolicyRosterRequest{
		PolicyId: p.ID.String(),
	}), tok))
	if err != nil {
		t.Fatalf("GetPolicyRoster: %v", err)
	}
	var sawExplicit, sawVia bool
	for _, n := range resp.Msg.Requesters {
		if n.Source == "via_role" {
			sawVia = true
		}
		if n.SubjectId == explicit.ID.String() && n.Source == "explicit" {
			sawExplicit = true
		}
	}
	if !sawExplicit {
		t.Fatalf("explicit subject missing from roster: %+v", resp.Msg.Requesters)
	}
	if sawVia {
		t.Fatalf("role-derived holder leaked to policy:read-only caller: %+v", resp.Msg.Requesters)
	}
}
