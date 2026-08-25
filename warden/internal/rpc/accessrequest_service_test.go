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
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

func pgU(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// TestAccessRequestRPCFlow exercises request→approve→grant over ConnectRPC plus
// the authz sentinel→Connect-code mappings.
func TestAccessRequestRPCFlow(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	target := mkRole("db-admin-flow")
	requesterRole := mkRole("requester-flow")
	approverRole := mkRole("approver-flow")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-flow"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg-flow", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
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
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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

// TestListReviewableGrants verifies the review-scoped grant list: the grant's
// subject and any standing potential approver of the grant's originating
// (role, asset) can review it; an unrelated user sees nothing. This mirrors the
// per-row authz of CanReviewGrant, applied as a self-scoping list filter.
func TestListReviewableGrants(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	targetRole := mkRole("lrg-target")
	requesterRole := mkRole("lrg-requester")
	approverRole := mkRole("lrg-approver")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "lrg-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "lrg-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: targetRole, ScopeAssetID: pgU(asset.ID), RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	// alice = subject (requester), bob = standing potential approver, mallory = unrelated.
	seedUser(t, pool, "lrg-alice@x", "password123", false)
	seedUser(t, pool, "lrg-bob@x", "password123", false)
	seedUser(t, pool, "lrg-mallory@x", "password123", false)
	aliceUID := userIDByEmail(t, pool, "lrg-alice@x")
	bobUID := userIDByEmail(t, pool, "lrg-bob@x")

	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: requesterRole, ScopeAssetID: pgU(asset.ID), SubjectUserID: pgU(aliceUID),
	}); err != nil {
		t.Fatalf("bind requester: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: approverRole, ScopeAssetID: pgU(asset.ID), SubjectUserID: pgU(bobUID),
	}); err != nil {
		t.Fatalf("bind approver: %v", err)
	}

	aliceTok := authClient(t, url, "lrg-alice@x", "password123")
	bobTok := authClient(t, url, "lrg-bob@x", "password123")
	malloryTok := authClient(t, url, "lrg-mallory@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// alice requests → bob approves → a completed grant, subject=alice.
	r, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: targetRole.String(), AssetId: asset.ID.String(), DurationSeconds: 3600,
	}), aliceTok))
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if _, err := client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{
		RequestId: r.Msg.Request.Id,
	}), bobTok)); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	countReviewable := func(tok string) int {
		resp, err := client.ListReviewableGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListReviewableGrantsRequest{}), tok))
		if err != nil {
			t.Fatalf("ListReviewableGrants: %v", err)
		}
		return len(resp.Msg.Grants)
	}

	// subject sees it
	if n := countReviewable(aliceTok); n != 1 {
		t.Fatalf("subject: %d, want 1", n)
	}
	// standing potential approver sees it
	if n := countReviewable(bobTok); n != 1 {
		t.Fatalf("approver: %d, want 1", n)
	}
	// unrelated user does not
	if n := countReviewable(malloryTok); n != 0 {
		t.Fatalf("unrelated: %d, want 0", n)
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
		Name: "db-admin", Capabilities: []string{"db:read", "db:write"},
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
		FolderId: folder.Msg.Folder.Id, Name: "pg-prod", Config: emptySSHConfig(),
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
		Name: "no-rule-role", Capabilities: []string{"db:read"},
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

// TestAccessRequestAdminGating asserts ListGrants is gated by the global
// access:grant:read capability: a plain authenticated user (no caps) is denied,
// a user holding access:grant:read globally is allowed, and the bootstrap admin
// (**) is allowed.
func TestAccessRequestAdminGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "plain@x", "password123", false)
	atok := adminToken(t, url)
	ptok := authClient(t, url, "plain@x", "password123")

	// grantReader holds access:grant:read globally.
	seedUser(t, pool, "reader@x", "password123", false)
	bindScopedCap(t, pool, userIDByEmail(t, pool, "reader@x"), `["access:grant:read"]`, uuid.Nil, uuid.Nil)
	gtok := authClient(t, url, "reader@x", "password123")

	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// Plain user without the cap → PermissionDenied.
	if _, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{}), ptok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("plain ListGrants = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// User holding access:grant:read → allowed.
	if _, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{}), gtok)); err != nil {
		t.Fatalf("reader ListGrants = %v, want ok", err)
	}
	// Admin (**) → allowed.
	if _, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{}), atok)); err != nil {
		t.Fatalf("admin ListGrants = %v, want ok", err)
	}
}

// TestListMyRequestsKeysetPagination verifies (created_at DESC, id) keyset
// pagination for ListMyRequests. Seeds 3 requests by a single requester
// (one per asset, since only one pending per role+asset is allowed), pages
// with page_size=2, asserts newest-first ordering and token termination.
func TestListMyRequestsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	// Roles: one target role, one requester role.
	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	targetRole := mkRole("myr-target")
	requesterRole := mkRole("myr-requester")
	approverRole := mkRole("myr-approver")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "myr-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// Create 3 assets so we can place 3 distinct requests (one per asset).
	assets := make([]uuid.UUID, 3)
	for i, name := range []string{"myr-asset-a", "myr-asset-b", "myr-asset-c"} {
		a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatalf("CreateAsset %s: %v", name, err)
		}
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID: targetRole, ScopeAssetID: pgU(a.ID), RequiredApprovals: 1,
			ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
		}); err != nil {
			t.Fatalf("CreateRequestPolicy %s: %v", name, err)
		}
		assets[i] = a.ID
	}

	seedUser(t, pool, "myr-req@x", "password123", false)
	seedUser(t, pool, "myr-app@x", "password123", false)
	reqUID := userIDByEmail(t, pool, "myr-req@x")
	appUID := userIDByEmail(t, pool, "myr-app@x")

	// Bind requester and approver on all 3 assets.
	for _, aid := range assets {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: requesterRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(reqUID),
		}); err != nil {
			t.Fatalf("bind requester: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: approverRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(appUID),
		}); err != nil {
			t.Fatalf("bind approver: %v", err)
		}
	}

	reqTok := authClient(t, url, "myr-req@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Submit 3 requests (oldest first by creation order).
	var reqIDs []string
	for _, aid := range assets {
		r, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
			RoleId: targetRole.String(), AssetId: aid.String(), DurationSeconds: 3600,
		}), reqTok))
		if err != nil {
			t.Fatalf("RequestAccess: %v", err)
		}
		reqIDs = append(reqIDs, r.Msg.Request.Id)
	}
	// reqIDs[0] = oldest, reqIDs[2] = newest.

	// Page 1: 2 items (newest first), must have a token.
	page1, err := client.ListMyRequests(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyRequestsRequest{
		PageSize: 2,
	}), reqTok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Requests) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1.Msg.Requests))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	// Newest first: reqIDs[2], reqIDs[1].
	if page1.Msg.Requests[0].Id != reqIDs[2] {
		t.Fatalf("page1[0] = %s, want %s (newest)", page1.Msg.Requests[0].Id, reqIDs[2])
	}
	if page1.Msg.Requests[1].Id != reqIDs[1] {
		t.Fatalf("page1[1] = %s, want %s", page1.Msg.Requests[1].Id, reqIDs[1])
	}

	// Page 2: 1 remaining item (oldest), no token.
	page2, err := client.ListMyRequests(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyRequestsRequest{
		PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), reqTok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Requests) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2.Msg.Requests))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Requests[0].Id != reqIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest)", page2.Msg.Requests[0].Id, reqIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, r := range append(page1.Msg.Requests, page2.Msg.Requests...) {
		if seen[r.Id] {
			t.Fatalf("duplicate request %s across pages", r.Id)
		}
		seen[r.Id] = true
	}
	if len(seen) != 3 {
		t.Fatalf("total = %d, want 3", len(seen))
	}
}

// TestListPendingApprovalsKeysetPagination verifies (created_at DESC, id) keyset
// pagination for ListPendingApprovals. Seeds 3 pending requests the caller can
// approve, pages with page_size=2, asserts newest-first ordering and termination.
func TestListPendingApprovalsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	targetRole := mkRole("lpa-target")
	requesterRole := mkRole("lpa-requester")
	approverRole := mkRole("lpa-approver")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "lpa-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// 3 assets → 3 distinct pending requests.
	assets := make([]uuid.UUID, 3)
	for i, name := range []string{"lpa-a", "lpa-b", "lpa-c"} {
		a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatalf("CreateAsset %s: %v", name, err)
		}
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID: targetRole, ScopeAssetID: pgU(a.ID), RequiredApprovals: 1,
			ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
		}); err != nil {
			t.Fatalf("CreateRequestPolicy %s: %v", name, err)
		}
		assets[i] = a.ID
	}

	seedUser(t, pool, "lpa-req@x", "password123", false)
	seedUser(t, pool, "lpa-app@x", "password123", false)
	reqUID := userIDByEmail(t, pool, "lpa-req@x")
	appUID := userIDByEmail(t, pool, "lpa-app@x")

	for _, aid := range assets {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: requesterRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(reqUID),
		}); err != nil {
			t.Fatalf("bind requester: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: approverRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(appUID),
		}); err != nil {
			t.Fatalf("bind approver: %v", err)
		}
	}

	reqTok := authClient(t, url, "lpa-req@x", "password123")
	appTok := authClient(t, url, "lpa-app@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Submit 3 pending requests (oldest first).
	var reqIDs []string
	for _, aid := range assets {
		r, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
			RoleId: targetRole.String(), AssetId: aid.String(), DurationSeconds: 3600,
		}), reqTok))
		if err != nil {
			t.Fatalf("RequestAccess: %v", err)
		}
		reqIDs = append(reqIDs, r.Msg.Request.Id)
	}

	// Page 1: 2 items (newest first), must have a token.
	page1, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{
		PageSize: 2,
	}), appTok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Requests) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1.Msg.Requests))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	// Newest first: reqIDs[2], reqIDs[1].
	if page1.Msg.Requests[0].Id != reqIDs[2] {
		t.Fatalf("page1[0] = %s, want %s (newest)", page1.Msg.Requests[0].Id, reqIDs[2])
	}
	if page1.Msg.Requests[1].Id != reqIDs[1] {
		t.Fatalf("page1[1] = %s, want %s", page1.Msg.Requests[1].Id, reqIDs[1])
	}

	// Page 2: 1 remaining item (oldest), no token.
	page2, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{
		PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), appTok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Requests) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2.Msg.Requests))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Requests[0].Id != reqIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest)", page2.Msg.Requests[0].Id, reqIDs[0])
	}

	// Verify caller scoping: the requester themselves sees no pending approvals.
	mine, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{}), reqTok))
	if err != nil {
		t.Fatalf("requester ListPendingApprovals: %v", err)
	}
	if len(mine.Msg.Requests) != 0 {
		t.Fatalf("requester should see 0 pending approvals, got %d", len(mine.Msg.Requests))
	}
}

// TestListMyGrantsKeysetPagination verifies (granted_at DESC, id) keyset
// pagination for ListMyGrants. Seeds 3 grants by approving 3 requests (one
// per asset), pages with page_size=2, asserts newest-first ordering and
// token termination. Uses granted_at NOT created_at (access_grants has no created_at).
func TestListMyGrantsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	targetRole := mkRole("lmg-target")
	requesterRole := mkRole("lmg-requester")
	approverRole := mkRole("lmg-approver")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "lmg-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	assets := make([]uuid.UUID, 3)
	for i, name := range []string{"lmg-a", "lmg-b", "lmg-c"} {
		a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatalf("CreateAsset %s: %v", name, err)
		}
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID: targetRole, ScopeAssetID: pgU(a.ID), RequiredApprovals: 1,
			ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
		}); err != nil {
			t.Fatalf("CreateRequestPolicy %s: %v", name, err)
		}
		assets[i] = a.ID
	}

	seedUser(t, pool, "lmg-req@x", "password123", false)
	seedUser(t, pool, "lmg-app@x", "password123", false)
	reqUID := userIDByEmail(t, pool, "lmg-req@x")
	appUID := userIDByEmail(t, pool, "lmg-app@x")

	for _, aid := range assets {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: requesterRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(reqUID),
		}); err != nil {
			t.Fatalf("bind requester: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: approverRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(appUID),
		}); err != nil {
			t.Fatalf("bind approver: %v", err)
		}
	}

	reqTok := authClient(t, url, "lmg-req@x", "password123")
	appTok := authClient(t, url, "lmg-app@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Submit 3 requests then approve each to mint 3 grants.
	var grantIDs []string
	for _, aid := range assets {
		r, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
			RoleId: targetRole.String(), AssetId: aid.String(), DurationSeconds: 3600,
		}), reqTok))
		if err != nil {
			t.Fatalf("RequestAccess: %v", err)
		}
		appr, err := client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{
			RequestId: r.Msg.Request.Id,
		}), appTok))
		if err != nil {
			t.Fatalf("ApproveRequest: %v", err)
		}
		grantIDs = append(grantIDs, appr.Msg.Request.GrantId)
	}
	// grantIDs[0] = oldest granted_at, grantIDs[2] = newest.

	// Page 1: 2 items (newest first), must have a token.
	page1, err := client.ListMyGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyGrantsRequest{
		PageSize: 2,
	}), reqTok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Grants) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1.Msg.Grants))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	// Newest first: grantIDs[2], grantIDs[1].
	if page1.Msg.Grants[0].Id != grantIDs[2] {
		t.Fatalf("page1[0] = %s, want %s (newest granted_at)", page1.Msg.Grants[0].Id, grantIDs[2])
	}
	if page1.Msg.Grants[1].Id != grantIDs[1] {
		t.Fatalf("page1[1] = %s, want %s", page1.Msg.Grants[1].Id, grantIDs[1])
	}

	// Page 2: 1 remaining item (oldest), no token.
	page2, err := client.ListMyGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyGrantsRequest{
		PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), reqTok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Grants) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2.Msg.Grants))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Grants[0].Id != grantIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest)", page2.Msg.Grants[0].Id, grantIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, g := range append(page1.Msg.Grants, page2.Msg.Grants...) {
		if seen[g.Id] {
			t.Fatalf("duplicate grant %s across pages", g.Id)
		}
		seen[g.Id] = true
	}
	if len(seen) != 3 {
		t.Fatalf("total grants = %d, want 3", len(seen))
	}

	// asset_path must be populated (e.g. "lmg-c.lmg-folder") for all grants.
	// logins is empty because lmg-target has no ssh:login caps.
	for _, g := range append(page1.Msg.Grants, page2.Msg.Grants...) {
		if g.AssetPath == "" {
			t.Errorf("grant %s: AssetPath is empty, want non-empty DNS path", g.Id)
		}
		if len(g.Logins) != 0 {
			t.Errorf("grant %s: Logins = %v, want empty (role has no ssh:login caps)", g.Id, g.Logins)
		}
	}

	// Verify asset_path format for page1[0] (newest = lmg-c in lmg-folder).
	// DNS-style: "<asset>.<folder>", i.e. "lmg-c.lmg-folder".
	wantPath := "lmg-c.lmg-folder"
	if page1.Msg.Grants[0].AssetPath != wantPath {
		t.Errorf("page1[0].AssetPath = %q, want %q", page1.Msg.Grants[0].AssetPath, wantPath)
	}

	// Create a role with ssh:login caps and verify logins are extracted.
	sshRole := createRoleWithCaps(t, ctx, q, "lmg-ssh-role", pgtype.UUID{}, `["ssh:login:root","ssh:login:deploy"]`)
	sshAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "lmg-ssh", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset ssh: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: sshRole.ID, ScopeAssetID: pgU(sshAsset.ID), RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy ssh: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: requesterRole, ScopeAssetID: pgU(sshAsset.ID), SubjectUserID: pgU(reqUID),
	}); err != nil {
		t.Fatalf("bind requester ssh: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: approverRole, ScopeAssetID: pgU(sshAsset.ID), SubjectUserID: pgU(appUID),
	}); err != nil {
		t.Fatalf("bind approver ssh: %v", err)
	}
	sshReq, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: sshRole.ID.String(), AssetId: sshAsset.ID.String(), DurationSeconds: 3600,
	}), reqTok))
	if err != nil {
		t.Fatalf("RequestAccess ssh: %v", err)
	}
	if _, err := client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{
		RequestId: sshReq.Msg.Request.Id,
	}), appTok)); err != nil {
		t.Fatalf("ApproveRequest ssh: %v", err)
	}
	sshPage, err := client.ListMyGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListMyGrantsRequest{
		PageSize: 1,
	}), reqTok))
	if err != nil {
		t.Fatalf("ListMyGrants ssh: %v", err)
	}
	if len(sshPage.Msg.Grants) != 1 {
		t.Fatalf("ssh page: got %d grants, want 1", len(sshPage.Msg.Grants))
	}
	sshGrant := sshPage.Msg.Grants[0]
	if sshGrant.AssetPath != "lmg-ssh.lmg-folder" {
		t.Errorf("ssh grant AssetPath = %q, want %q", sshGrant.AssetPath, "lmg-ssh.lmg-folder")
	}
	wantLogins := map[string]bool{"root": true, "deploy": true}
	if len(sshGrant.Logins) != len(wantLogins) {
		t.Errorf("ssh grant Logins = %v, want [root deploy]", sshGrant.Logins)
	}
	for _, l := range sshGrant.Logins {
		if !wantLogins[l] {
			t.Errorf("ssh grant unexpected login %q", l)
		}
	}
}

// TestListGrantsKeysetPagination verifies (granted_at DESC, id) keyset pagination
// for the admin ListGrants RPC. Seeds ≥3 grants as an admin, pages with
// page_size=2, asserts newest-first ordering and termination. Also verifies
// the active_only and subject_user_id filters are still respected.
func TestListGrantsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	seedUser(t, pool, "admin@x", "supersecret", true)
	atok := adminToken(t, url)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}
	targetRole := mkRole("lg-target")
	requesterRole := mkRole("lg-requester")
	approverRole := mkRole("lg-approver")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "lg-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	assets := make([]uuid.UUID, 3)
	for i, name := range []string{"lg-a", "lg-b", "lg-c"} {
		a, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatalf("CreateAsset %s: %v", name, err)
		}
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID: targetRole, ScopeAssetID: pgU(a.ID), RequiredApprovals: 1,
			ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
		}); err != nil {
			t.Fatalf("CreateRequestPolicy %s: %v", name, err)
		}
		assets[i] = a.ID
	}

	seedUser(t, pool, "lg-req@x", "password123", false)
	seedUser(t, pool, "lg-app@x", "password123", false)
	reqUID := userIDByEmail(t, pool, "lg-req@x")
	appUID := userIDByEmail(t, pool, "lg-app@x")

	for _, aid := range assets {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: requesterRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(reqUID),
		}); err != nil {
			t.Fatalf("bind requester: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: approverRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(appUID),
		}); err != nil {
			t.Fatalf("bind approver: %v", err)
		}
	}

	reqTok := authClient(t, url, "lg-req@x", "password123")
	appTok := authClient(t, url, "lg-app@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Mint 3 grants.
	var grantIDs []string
	for _, aid := range assets {
		r, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
			RoleId: targetRole.String(), AssetId: aid.String(), DurationSeconds: 3600,
		}), reqTok))
		if err != nil {
			t.Fatalf("RequestAccess: %v", err)
		}
		appr, err := client.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{
			RequestId: r.Msg.Request.Id,
		}), appTok))
		if err != nil {
			t.Fatalf("ApproveRequest: %v", err)
		}
		grantIDs = append(grantIDs, appr.Msg.Request.GrantId)
	}
	// grantIDs[0] = oldest, grantIDs[2] = newest.

	// Page 1 (admin, no filter): 2 items newest-first, must have a token.
	page1, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{
		PageSize: 2,
	}), atok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Grants) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1.Msg.Grants))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}
	// Newest first: grantIDs[2], grantIDs[1].
	if page1.Msg.Grants[0].Id != grantIDs[2] {
		t.Fatalf("page1[0] = %s, want %s (newest granted_at)", page1.Msg.Grants[0].Id, grantIDs[2])
	}
	if page1.Msg.Grants[1].Id != grantIDs[1] {
		t.Fatalf("page1[1] = %s, want %s", page1.Msg.Grants[1].Id, grantIDs[1])
	}

	// Page 2: 1 remaining item (oldest), no token.
	page2, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{
		PageSize: 2, PageToken: page1.Msg.NextPageToken,
	}), atok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Grants) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2.Msg.Grants))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}
	if page2.Msg.Grants[0].Id != grantIDs[0] {
		t.Fatalf("page2[0] = %s, want %s (oldest)", page2.Msg.Grants[0].Id, grantIDs[0])
	}

	// No duplicates across pages.
	seen := map[string]bool{}
	for _, g := range append(page1.Msg.Grants, page2.Msg.Grants...) {
		if seen[g.Id] {
			t.Fatalf("duplicate grant %s across pages", g.Id)
		}
		seen[g.Id] = true
	}
	if len(seen) != 3 {
		t.Fatalf("total = %d, want 3", len(seen))
	}

	// subject_user_id filter: only the requester's grants.
	subjectFiltered, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{
		SubjectUserId: reqUID.String(),
	}), atok))
	if err != nil {
		t.Fatalf("subject filtered: %v", err)
	}
	if len(subjectFiltered.Msg.Grants) != 3 {
		t.Fatalf("subject filtered: got %d, want 3", len(subjectFiltered.Msg.Grants))
	}
	for _, g := range subjectFiltered.Msg.Grants {
		if g.SubjectUserId != reqUID.String() {
			t.Fatalf("unexpected subject %s in filtered result", g.SubjectUserId)
		}
	}

	// active_only filter: all 3 are still active (not yet expired/revoked).
	activeOnly, err := client.ListGrants(ctx, withToken(connect.NewRequest(&accessrequestv1.ListGrantsRequest{
		ActiveOnly: true,
	}), atok))
	if err != nil {
		t.Fatalf("active_only: %v", err)
	}
	if len(activeOnly.Msg.Grants) != 3 {
		t.Fatalf("active_only: got %d, want 3", len(activeOnly.Msg.Grants))
	}
	for _, g := range activeOnly.Msg.Grants {
		if !g.Active {
			t.Fatalf("grant %s not active in active_only result", g.Id)
		}
	}
}

// TestListPendingApprovalsPaginationAdvancesPastFilteredRows is a regression
// test for the keyset-over-post-filter bug: when the SQL page is full but all
// (or some) rows are filtered out by the Go-side IsApprover check, the handler
// must still emit a NextPageToken so the client can advance past those filtered
// rows on subsequent calls.
//
// Setup:
//   - Two policies, P1 and P2, each on a distinct asset.
//   - The caller (approver) holds the approver role for P1 only — NOT P2.
//   - One request is created for P1 (older created_at).
//   - One request is created for P2 (newer created_at).
//
// With page_size=1 the SQL page is: [P2 request] (newest first).
// That row is filtered out (caller cannot approve P2), but the SQL page WAS
// full, so a NextPageToken must be emitted.  Following that token yields the
// P1 request.  Old code would have emitted no token and the P1 request would
// have been permanently invisible to this caller.
func TestListPendingApprovalsPaginationAdvancesPastFilteredRows(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	mkRole := func(name string) uuid.UUID {
		return createRoleWithCaps(t, ctx, q, name, pgtype.UUID{}, "[]").ID
	}

	// Two independent target roles, two independent approver roles.
	targetRole1 := mkRole("filter-target1")
	targetRole2 := mkRole("filter-target2")
	requesterRole := mkRole("filter-requester")
	approverRole1 := mkRole("filter-approver1")
	approverRole2 := mkRole("filter-approver2")

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "filter-folder"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	// asset1 → P1 (approvable by caller), asset2 → P2 (NOT approvable by caller).
	asset1, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "filter-a1", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset asset1: %v", err)
	}
	asset2, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "filter-a2", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset asset2: %v", err)
	}

	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: targetRole1, ScopeAssetID: pgU(asset1.ID), RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole1), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy P1: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID: targetRole2, ScopeAssetID: pgU(asset2.ID), RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole2), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy P2: %v", err)
	}

	// Seed three users: requester, the approver (can approve P1 only), and an
	// unrelated approver2 who holds approverRole2 (included only for completeness).
	seedUser(t, pool, "filter-req@x", "password123", false)
	seedUser(t, pool, "filter-app@x", "password123", false)
	reqUID := userIDByEmail(t, pool, "filter-req@x")
	appUID := userIDByEmail(t, pool, "filter-app@x")

	// Requester is eligible on both assets.
	for _, aid := range []uuid.UUID{asset1.ID, asset2.ID} {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: requesterRole, ScopeAssetID: pgU(aid), SubjectUserID: pgU(reqUID),
		}); err != nil {
			t.Fatalf("bind requester on asset: %v", err)
		}
	}
	// Caller holds approverRole1 on asset1 ONLY — NOT approverRole2 on asset2.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: approverRole1, ScopeAssetID: pgU(asset1.ID), SubjectUserID: pgU(appUID),
	}); err != nil {
		t.Fatalf("bind approver on asset1: %v", err)
	}

	reqTok := authClient(t, url, "filter-req@x", "password123")
	appTok := authClient(t, url, "filter-app@x", "password123")
	client := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)

	// Submit P1 request first (older created_at), then P2 (newer created_at).
	// The list orders newest-first, so P2 appears on the first SQL page.
	r1, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: targetRole1.String(), AssetId: asset1.ID.String(), DurationSeconds: 3600,
	}), reqTok))
	if err != nil {
		t.Fatalf("RequestAccess P1: %v", err)
	}
	p1ReqID := r1.Msg.Request.Id

	r2, err := client.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: targetRole2.String(), AssetId: asset2.ID.String(), DurationSeconds: 3600,
	}), reqTok))
	if err != nil {
		t.Fatalf("RequestAccess P2: %v", err)
	}
	p2ReqID := r2.Msg.Request.Id

	// Page 1 (page_size=1): SQL returns the newest row (P2). The caller cannot
	// approve P2, so the filtered result is empty — but the SQL page was FULL,
	// so a NextPageToken MUST be present.
	page1, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{
		PageSize: 1,
	}), appTok))
	if err != nil {
		t.Fatalf("page1 ListPendingApprovals: %v", err)
	}
	// Filtered result is empty: P2 was the only SQL row and was filtered out.
	if len(page1.Msg.Requests) != 0 {
		t.Fatalf("page1 filtered count = %d, want 0 (P2 should be filtered out)", len(page1.Msg.Requests))
	}
	// Token MUST be emitted because the SQL page was full.
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: NextPageToken must be non-empty when SQL page was full, even if all rows were filtered out (regression: old code would stop here)")
	}

	// Follow tokens to exhaustion, collecting all visible requests.
	// The keyset-over-post-filter contract: pages may be short or empty, and an
	// exact-multiple-of-page_size page costs one extra empty round-trip.  We
	// just drain until no token is returned.
	var allVisible []*accessrequestv1.AccessRequest
	allVisible = append(allVisible, page1.Msg.Requests...)
	token := page1.Msg.NextPageToken
	for token != "" {
		resp, err := client.ListPendingApprovals(ctx, withToken(connect.NewRequest(&accessrequestv1.ListPendingApprovalsRequest{
			PageSize: 1, PageToken: token,
		}), appTok))
		if err != nil {
			t.Fatalf("follow token: %v", err)
		}
		allVisible = append(allVisible, resp.Msg.Requests...)
		token = resp.Msg.NextPageToken
	}

	// The caller must have seen exactly the P1 request.
	if len(allVisible) != 1 {
		t.Fatalf("total visible requests = %d, want 1 (only P1)", len(allVisible))
	}
	if allVisible[0].Id != p1ReqID {
		t.Fatalf("visible[0] = %s, want P1 request %s", allVisible[0].Id, p1ReqID)
	}
	// P2 must never appear.
	for _, r := range allVisible {
		if r.Id == p2ReqID {
			t.Fatalf("P2 request %s should not appear in approver's pending list (caller is not approver for P2)", p2ReqID)
		}
	}
}
