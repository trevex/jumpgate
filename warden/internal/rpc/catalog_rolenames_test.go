package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// TestGetAssetAccessRoleNames verifies that discovery reads surface role NAMES and
// the asset's DNS path: a requester (a user with a requestable-only role via a
// request policy) sees the requestable role by name via GetAssetAccess, and the
// asset carries its dotted path in ListVisibleAssets.
func TestGetAssetAccessRoleNames(t *testing.T) {
	pool, url := newServer(t)
	ctx := context.Background()
	q := gen.New(pool)

	// Folder + asset: box.prod
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "box", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	assetID := asset.ID.String()

	// The target role is folder-scoped to prod so folder_path resolves to "prod".
	target, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name:         "prod-shell",
		FolderID:     pgU(folder.ID),
		Capabilities: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("CreateRole target: %v", err)
	}
	// A global requester role the user standingly holds; it gates requestability of target.
	requesterRole, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "requester", Capabilities: []byte("[]")})
	if err != nil {
		t.Fatalf("CreateRole requester: %v", err)
	}

	// Request policy: target is requestable by holders of requesterRole.
	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: target.ID, RequiredApprovals: 1, RequesterRoleID: pgU(requesterRole.ID),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	// The user standingly holds requesterRole on the asset (so target is REQUESTABLE,
	// not active, to them).
	seedUser(t, pool, "req@x", "password123", false)
	var uid uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", "req@x").Scan(&uid); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: requesterRole.ID, ScopeAssetID: pgU(asset.ID), SubjectUserID: pgU(uid),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	utok := authClient(t, url, "req@x", "password123")
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)

	// The requestable role is visible BY NAME (and folder path), not just by id.
	acc, err := cat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: assetID}), utok))
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	var found bool
	for _, rr := range acc.Msg.GetRequestableRoles() {
		if rr.GetName() == "prod-shell" {
			found = true
			if rr.GetId() != target.ID.String() {
				t.Fatalf("role ref id = %q, want %q", rr.GetId(), target.ID.String())
			}
			if rr.GetFolderPath() != "prod" {
				t.Fatalf("role ref folder_path = %q, want %q", rr.GetFolderPath(), "prod")
			}
		}
	}
	if !found {
		t.Fatalf("requestable role not visible by name: %+v", acc.Msg.GetRequestableRoles())
	}

	// The visible list carries the DNS path (box.prod).
	vis, err := cat.ListVisibleAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListVisibleAssetsRequest{}), utok))
	if err != nil {
		t.Fatalf("visible: %v", err)
	}
	var sawPath bool
	for _, a := range vis.Msg.GetAssets() {
		if a.GetId() == assetID && a.GetPath() == "box.prod" {
			sawPath = true
		}
	}
	if !sawPath {
		t.Fatalf("asset path missing from visible list: %+v", vis.Msg.GetAssets())
	}
}
