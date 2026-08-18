package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

func TestPerUserVisibilityCatalog(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustF := func(name, parent string) string {
		r, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: name, ParentId: parent}), tok))
		if err != nil {
			t.Fatalf("folder %s: %v", name, err)
		}
		return r.Msg.Folder.Id
	}
	mustA := func(folder, name string) string {
		r, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: folder, Name: name}), tok))
		if err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return r.Msg.Asset.Id
	}

	// alice (non-admin) in group sre
	alice, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "alice@x", DisplayName: "Alice", Password: "password123"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	sre, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{GroupId: sre.Msg.Group.Id, UserId: alice.Msg.User.Id}), tok)); err != nil {
		t.Fatal(err)
	}

	prod := mustF("prod", "")
	pgprod := mustA(prod, "pg-prod")
	secret := mustF("secret", "")
	topsecret := mustA(secret, "top-secret")

	role, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{Name: "readonly", ResourceType: "asset", Capabilities: []string{"db:read"}}), tok))
	if err != nil {
		t.Fatal(err)
	}
	// readonly cascades down folders via an explicit parent self-rule; seed the
	// cascade rule directly via the DB for test setup.
	roleID := uuid.MustParse(role.Msg.Role.Id)
	if _, err := gen.New(pool).CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: roleID, SourceRoleID: roleID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}
	// STANDING binding: sre -> readonly on folder prod
	if _, err := cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: role.Msg.Role.Id, Kind: "standing", ScopeFolderId: prod, SubjectGroupId: sre.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatal(err)
	}

	// --- act as alice ---
	atok := authClient(t, url, "alice@x", "password123")
	acat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)

	vis, err := acat.ListVisibleAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListVisibleAssetsRequest{}), atok))
	if err != nil {
		t.Fatalf("visible: %v", err)
	}
	seen := map[string]bool{}
	for _, a := range vis.Msg.Assets {
		seen[a.Id] = a.Active
	}
	if active, ok := seen[pgprod]; !ok || !active {
		t.Fatalf("pg-prod: want visible+active, got ok=%v active=%v", ok, active)
	}
	if _, ok := seen[topsecret]; ok {
		t.Fatal("top-secret must be invisible to alice")
	}

	// GetAssetAccess on the visible asset returns the readonly role
	acc, err := acat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: pgprod}), atok))
	if err != nil {
		t.Fatalf("access pgprod: %v", err)
	}
	if len(acc.Msg.ActiveRoleIds) != 1 || acc.Msg.ActiveRoleIds[0] != role.Msg.Role.Id {
		t.Fatalf("pgprod active roles = %v, want [%s]", acc.Msg.ActiveRoleIds, role.Msg.Role.Id)
	}

	// GetAssetAccess on an invisible asset → NotFound (no existence leak)
	_, err = acat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: topsecret}), atok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("access top-secret = %v, want NotFound", connect.CodeOf(err))
	}

	// GetAssetAccess on a random uuid → NotFound
	_, err = acat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: "11111111-1111-1111-1111-111111111111"}), atok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("access random = %v, want NotFound", connect.CodeOf(err))
	}
}
