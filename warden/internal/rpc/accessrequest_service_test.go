package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

func pgU(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// TestAccessRequestRPCFlow exercises request→approve→grant over ConnectRPC plus
// the authz sentinel→Connect-code mappings.
func TestAccessRequestRPCFlow(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := gen.New(pool)

	mkRole := func(name string) uuid.UUID {
		r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name, ResourceType: "asset", Capabilities: []byte("[]")})
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		return r.ID
	}
	target := mkRole("db-admin-flow")
	requesterRole := mkRole("requester-flow")
	approverRole := mkRole("approver-flow")

	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod-flow"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg-flow", Labels: []byte("{}")})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: target, RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	userID := func(pool *pgxpool.Pool, email string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&id); err != nil {
			t.Fatalf("lookup user %s: %v", email, err)
		}
		return id
	}
	bind := func(uid, roleID uuid.UUID) {
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: roleID, ScopeAssetID: pgU(asset.ID), SubjectUserID: pgU(uid),
		}); err != nil {
			t.Fatalf("CreateRoleBinding: %v", err)
		}
	}

	seedUser(t, pool, "req@flow", "password123", false)
	seedUser(t, pool, "app@flow", "password123", false)
	seedUser(t, pool, "stranger@flow", "password123", false)
	bind(userID(pool, "req@flow"), requesterRole)
	bind(userID(pool, "app@flow"), approverRole)

	reqTok := authClient(t, url, "req@flow", "password123")
	appTok := authClient(t, url, "app@flow", "password123")
	strangerTok := authClient(t, url, "stranger@flow", "password123")

	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Unauthenticated → Unauthenticated.
	_, err = client.RequestAccess(ctx, connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: target.String(), AssetId: asset.ID.String(), DurationSeconds: 3600,
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anon RequestAccess = %v, want Unauthenticated", connect.CodeOf(err))
	}

	// Ineligible requester → NotFound (existence-hiding).
	_, err = client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: target.String(), AssetId: asset.ID.String(), DurationSeconds: 3600,
	}), strangerTok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("ineligible RequestAccess = %v, want NotFound", connect.CodeOf(err))
	}

	// Eligible requester opens the request.
	resp, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: target.String(), AssetId: asset.ID.String(), DurationSeconds: 3600, Reason: "incident",
	}), reqTok))
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if resp.Msg.Request.Status != "pending" {
		t.Fatalf("status = %q, want pending", resp.Msg.Request.Status)
	}
	reqID := resp.Msg.Request.Id

	// Duplicate pending → AlreadyExists.
	_, err = client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: target.String(), AssetId: asset.ID.String(), DurationSeconds: 3600,
	}), reqTok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("dup RequestAccess = %v, want AlreadyExists", connect.CodeOf(err))
	}

	// Non-approver Approve → PermissionDenied.
	_, err = client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{RequestId: reqID}), strangerTok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-approver Approve = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Approver sees it pending; requester does not.
	pend, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{}), appTok))
	if err != nil {
		t.Fatalf("ListPendingApprovals: %v", err)
	}
	if len(pend.Msg.Requests) != 1 || pend.Msg.Requests[0].Id != reqID {
		t.Fatalf("pending = %+v, want [%s]", pend.Msg.Requests, reqID)
	}

	// Approve → granted + grant id.
	appr, err := client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{RequestId: reqID}), appTok))
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	if appr.Msg.Request.Status != "granted" || appr.Msg.Request.GrantId == "" {
		t.Fatalf("approve = %+v, want granted + grant_id", appr.Msg.Request)
	}

	// Requester's list shows the granted request.
	mine, err := client.ListMyRequests(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyRequestsRequest{}), reqTok))
	if err != nil {
		t.Fatalf("ListMyRequests: %v", err)
	}
	if len(mine.Msg.Requests) != 1 || mine.Msg.Requests[0].Status != "granted" || mine.Msg.Requests[0].GrantId == "" {
		t.Fatalf("my requests = %+v, want one granted with grant_id", mine.Msg.Requests)
	}

	// Re-approve → FailedPrecondition.
	_, err = client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{RequestId: reqID}), appTok))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("re-approve = %v, want FailedPrecondition", connect.CodeOf(err))
	}
}

func TestResolveApproval(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	ctx := context.Background()

	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	acc := accessv1connect.NewAccessServiceClient(http.DefaultClient, url)
	ar := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Create a role.
	role, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "db-admin", ResourceType: "asset", Capabilities: []string{"db:read", "db:write"},
	}), tok))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	roleID := role.Msg.Role.Id

	// Create a folder + asset.
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

	// Create a role-default request policy, required=2.
	if _, err := acc.CreateRequestPolicy(ctx, withToken(connect.NewRequest(&accessv1.CreateRequestPolicyRequest{
		RoleId:            roleID,
		RequiredApprovals: 2,
	}), tok)); err != nil {
		t.Fatalf("create request policy: %v", err)
	}

	// non-admin ResolveApproval → PermissionDenied
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
		RoleId: roleID, AssetId: assetID,
	}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin ResolveApproval = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// ResolveApproval for role with policy → requestable=true, required=2
	res, err := ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
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

	// Create a second role with no policy → ResolveApproval requestable=false
	role2, err := acc.CreateRole(ctx, withToken(connect.NewRequest(&accessv1.CreateRoleRequest{
		Name: "no-rule-role", ResourceType: "asset", Capabilities: []string{"db:read"},
	}), tok))
	if err != nil {
		t.Fatalf("create role2: %v", err)
	}
	res2, err := ar.ResolveApproval(ctx, withToken(connect.NewRequest(&accessrequestv1.ResolveApprovalRequest{
		RoleId:  role2.Msg.Role.Id,
		AssetId: assetID,
	}), tok))
	if err != nil {
		t.Fatalf("resolve approval (no rule): %v", err)
	}
	if res2.Msg.Requestable {
		t.Fatal("want requestable=false for role with no rule")
	}
}
