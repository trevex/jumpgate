package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	approvalv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/approval/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/approval/v1/approvalv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

func TestApprovalServiceCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ap := approvalv1connect.NewApprovalServiceClient(http.DefaultClient, url)

	// Create a role via catalog
	role, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{
		Name: "db-admin", ResourceType: "asset", Capabilities: []string{"read", "write"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	// Create a folder + asset for ResolveApproval
	folder, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: "prod"}), tok))
	if err != nil {
		t.Fatalf("create folder: %v", err)
	}
	asset, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folder.Msg.Folder.Id, Name: "pg-prod",
	}), tok))
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	assetID := asset.Msg.Asset.Id

	// Create a group to use as approver subject
	g, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "dba-approvers"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// non-admin CreateApprovalRule → PermissionDenied
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = ap.CreateApprovalRule(ctx, withToken(connect.NewRequest(&approvalv1.CreateApprovalRuleRequest{
		RoleId: roleID, RequiredApprovals: 1,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin CreateApprovalRule = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// CreateApprovalRule with BOTH scope_folder_id and scope_asset_id → InvalidArgument
	_, err = ap.CreateApprovalRule(ctx, withToken(connect.NewRequest(&approvalv1.CreateApprovalRuleRequest{
		RoleId:            roleID,
		ScopeFolderId:     folder.Msg.Folder.Id,
		ScopeAssetId:      assetID,
		RequiredApprovals: 2,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-scope CreateApprovalRule = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// Create a role-default approval rule (both scope fields empty), required=2
	rule, err := ap.CreateApprovalRule(ctx, withToken(connect.NewRequest(&approvalv1.CreateApprovalRuleRequest{
		RoleId:            roleID,
		RequiredApprovals: 2,
	}), tok))
	if err != nil {
		t.Fatalf("create approval rule: %v", err)
	}
	if rule.Msg.Rule.Id == "" {
		t.Fatal("expected non-empty rule id")
	}
	if rule.Msg.Rule.RequiredApprovals != 2 {
		t.Fatalf("required_approvals = %d, want 2", rule.Msg.Rule.RequiredApprovals)
	}
	ruleID := rule.Msg.Rule.Id

	// Add a group approver
	approver, err := ap.AddRuleApprover(ctx, withToken(connect.NewRequest(&approvalv1.AddRuleApproverRequest{
		RuleId:         ruleID,
		SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if err != nil {
		t.Fatalf("add rule approver: %v", err)
	}
	if approver.Msg.Id == "" {
		t.Fatal("expected non-empty approver id")
	}

	// AddRuleApprover with no subject → InvalidArgument
	_, err = ap.AddRuleApprover(ctx, withToken(connect.NewRequest(&approvalv1.AddRuleApproverRequest{
		RuleId: ruleID,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no-subject AddRuleApprover = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// AddRuleApprover with both subjects → InvalidArgument
	_, err = ap.AddRuleApprover(ctx, withToken(connect.NewRequest(&approvalv1.AddRuleApproverRequest{
		RuleId:         ruleID,
		SubjectUserId:  "00000000-0000-0000-0000-000000000001",
		SubjectGroupId: g.Msg.Group.Id,
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("two-subject AddRuleApprover = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// ListApprovalRules: should have >= 1
	rules, err := ap.ListApprovalRules(ctx, withToken(connect.NewRequest(&approvalv1.ListApprovalRulesRequest{
		RoleId: roleID,
	}), tok))
	if err != nil {
		t.Fatalf("list approval rules: %v", err)
	}
	if len(rules.Msg.Rules) < 1 {
		t.Fatalf("want >=1 rule, got %d", len(rules.Msg.Rules))
	}

	// ResolveApproval for role with rule → requestable=true, required=2
	res, err := ap.ResolveApproval(ctx, withToken(connect.NewRequest(&approvalv1.ResolveApprovalRequest{
		RoleId:  roleID,
		AssetId: assetID,
	}), tok))
	if err != nil {
		t.Fatalf("resolve approval: %v", err)
	}
	if !res.Msg.Requestable {
		t.Fatal("want requestable=true")
	}
	if res.Msg.RequiredApprovals != 2 {
		t.Fatalf("required_approvals = %d, want 2", res.Msg.RequiredApprovals)
	}

	// Create a second role with no rule → ResolveApproval requestable=false
	role2, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{
		Name: "no-rule-role", ResourceType: "asset", Capabilities: []string{"read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role2: %v", err)
	}
	res2, err := ap.ResolveApproval(ctx, withToken(connect.NewRequest(&approvalv1.ResolveApprovalRequest{
		RoleId:  role2.Msg.Role.Id,
		AssetId: assetID,
	}), tok))
	if err != nil {
		t.Fatalf("resolve approval (no rule): %v", err)
	}
	if res2.Msg.Requestable {
		t.Fatal("want requestable=false for role with no rule")
	}

	// RemoveRuleApprover
	if _, err := ap.RemoveRuleApprover(ctx, withToken(connect.NewRequest(&approvalv1.RemoveRuleApproverRequest{
		Id: approver.Msg.Id,
	}), tok)); err != nil {
		t.Fatalf("remove rule approver: %v", err)
	}

	// DeleteApprovalRule
	if _, err := ap.DeleteApprovalRule(ctx, withToken(connect.NewRequest(&approvalv1.DeleteApprovalRuleRequest{
		Id: ruleID,
	}), tok)); err != nil {
		t.Fatalf("delete approval rule: %v", err)
	}
}
