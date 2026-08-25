package rpc_test

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestListPoliciesForAssetAndGroup proves the two reverse policy-listing RPCs return
// the right policies: ListPoliciesForAsset returns policies scoped to the asset, and
// ListPoliciesForGroup returns policies the group is a subject of. Policies scoped to a
// different asset (resp. subjecting a different group) are excluded.
func TestListPoliciesForAssetAndGroup(t *testing.T) {
	f := setupCascade(t)
	ctx := f.ctx
	q := f.q

	roleID := f.createRole(t, "ssh-deploy")
	rUUID := uuid.MustParse(roleID)

	// A second asset (in the same folder) to prove scope filtering.
	baseAsset, err := q.GetAsset(ctx, f.asset)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	otherAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{
		FolderID: baseAsset.FolderID, Name: "pg2", Labels: []byte("{}"), Kind: "ssh",
	})
	if err != nil {
		t.Fatalf("CreateAsset other: %v", err)
	}

	// Asset-scoped policy on f.asset; a second policy on otherAsset that must NOT appear.
	pAsset, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: rUUID, ScopeAssetID: pgtype.UUID{Bytes: f.asset, Valid: true},
		RequiredApprovals: 2, Name: pgtype.Text{String: "on-asset", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateRequestPolicy asset: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: rUUID, ScopeAssetID: pgtype.UUID{Bytes: otherAsset.ID, Valid: true},
		RequiredApprovals: 1, Name: pgtype.Text{String: "on-other", Valid: true},
	}); err != nil {
		t.Fatalf("CreateRequestPolicy other: %v", err)
	}

	// A group made a subject of a (role-default) policy; a second group NOT a subject.
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "sre-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	otherGrp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "ops-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateGroup other: %v", err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID: pAsset.ID, Kind: "approver", SubjectGroupID: pgtype.UUID{Bytes: grp.ID, Valid: true},
	}); err != nil {
		t.Fatalf("AddPolicySubject: %v", err)
	}

	// ListPoliciesForAsset returns only the asset-scoped policy.
	forAsset, err := f.acc.ListPoliciesForAsset(ctx, withToken(connect.NewRequest(&accessv1.ListPoliciesForAssetRequest{
		AssetId: f.asset.String(), PageSize: 50,
	}), f.admin))
	if err != nil {
		t.Fatalf("ListPoliciesForAsset: %v", err)
	}
	if len(forAsset.Msg.Policies) != 1 || forAsset.Msg.Policies[0].Id != pAsset.ID.String() {
		t.Fatalf("ListPoliciesForAsset = %+v, want only %s", forAsset.Msg.Policies, pAsset.ID)
	}

	// ListPoliciesForGroup returns the policy the group subjects; the other group sees none.
	forGroup, err := f.acc.ListPoliciesForGroup(ctx, withToken(connect.NewRequest(&accessv1.ListPoliciesForGroupRequest{
		GroupId: grp.ID.String(), PageSize: 50,
	}), f.admin))
	if err != nil {
		t.Fatalf("ListPoliciesForGroup: %v", err)
	}
	if len(forGroup.Msg.Policies) != 1 || forGroup.Msg.Policies[0].Id != pAsset.ID.String() {
		t.Fatalf("ListPoliciesForGroup = %+v, want only %s", forGroup.Msg.Policies, pAsset.ID)
	}

	forOther, err := f.acc.ListPoliciesForGroup(ctx, withToken(connect.NewRequest(&accessv1.ListPoliciesForGroupRequest{
		GroupId: otherGrp.ID.String(), PageSize: 50,
	}), f.admin))
	if err != nil {
		t.Fatalf("ListPoliciesForGroup other: %v", err)
	}
	if len(forOther.Msg.Policies) != 0 {
		t.Fatalf("ListPoliciesForGroup(other) = %+v, want empty", forOther.Msg.Policies)
	}
}
