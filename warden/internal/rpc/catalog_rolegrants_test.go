package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

func TestRoleGrantCRUD(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	mustRole := func(name string) string {
		r, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{Name: name, ResourceType: "asset", Capabilities: []string{"read"}}), tok))
		if err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		return r.Msg.Role.Id
	}
	editor := mustRole("editor")
	owner := mustRole("owner")

	// editor ⊇ owner same_object
	g1, err := cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if err != nil {
		t.Fatalf("add same_object grant: %v", err)
	}
	if g1.Msg.Grant.Id == "" || g1.Msg.Grant.Via != "same_object" {
		t.Fatalf("unexpected grant %+v", g1.Msg.Grant)
	}
	// editor ⊇ editor parent (folder-cascade self-rule)
	if _, err := cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: editor, Via: "parent",
	}), tok)); err != nil {
		t.Fatalf("add parent grant: %v", err)
	}

	// list returns both
	lst, err := cat.ListRoleGrants(ctx, withToken(connect.NewRequest(&catalogv1.ListRoleGrantsRequest{RoleId: editor}), tok))
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(lst.Msg.Grants) != 2 {
		t.Fatalf("list grants = %d, want 2", len(lst.Msg.Grants))
	}

	// same_object self-reference → InvalidArgument
	_, err = cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{
		RoleId: owner, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("same-object self = %v, want InvalidArgument", connect.CodeOf(err))
	}

	// duplicate → AlreadyExists
	_, err = cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{
		RoleId: editor, SourceRoleId: owner, Via: "same_object",
	}), tok))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate = %v, want AlreadyExists", connect.CodeOf(err))
	}

	// remove then list shows it gone
	if _, err := cat.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.RemoveRoleGrantRequest{Id: g1.Msg.Grant.Id}), tok)); err != nil {
		t.Fatalf("remove grant: %v", err)
	}
	lst2, err := cat.ListRoleGrants(ctx, withToken(connect.NewRequest(&catalogv1.ListRoleGrantsRequest{RoleId: editor}), tok))
	if err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(lst2.Msg.Grants) != 1 {
		t.Fatalf("list after remove = %d, want 1", len(lst2.Msg.Grants))
	}

	// non-admin rejected on all admin ops
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	_, err = cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{RoleId: editor, SourceRoleId: owner, Via: "same_object"}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin add = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err = cat.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.RemoveRoleGrantRequest{Id: g1.Msg.Grant.Id}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin remove = %v, want PermissionDenied", connect.CodeOf(err))
	}
	_, err = cat.ListRoleGrants(ctx, withToken(connect.NewRequest(&catalogv1.ListRoleGrantsRequest{RoleId: editor}), utok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin list = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestExplainRole(t *testing.T) {
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
	// folder prod ⊃ db; asset pg in db.
	prod := mustF("prod", "")
	dbf := mustF("db", prod)
	pg, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: dbf, Name: "pg"}), tok))
	if err != nil {
		t.Fatalf("asset pg: %v", err)
	}
	pgID := pg.Msg.Asset.Id

	owner, err := cat.CreateRole(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleRequest{Name: "owner", ResourceType: "asset", Capabilities: []string{"*"}}), tok))
	if err != nil {
		t.Fatalf("role owner: %v", err)
	}
	ownerID := owner.Msg.Role.Id
	// owner ⊇ owner parent — cascades down the folder chain.
	if _, err := cat.AddRoleGrant(ctx, withToken(connect.NewRequest(&catalogv1.AddRoleGrantRequest{
		RoleId: ownerID, SourceRoleId: ownerID, Via: "parent",
	}), tok)); err != nil {
		t.Fatalf("owner parent grant: %v", err)
	}

	// alice (non-admin) in group sre; sre standing owner@prod.
	alice, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "alice@x", DisplayName: "Alice", Password: "password123"}), tok))
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	aliceID := alice.Msg.User.Id
	sre, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := id.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{GroupId: sre.Msg.Group.Id, UserId: aliceID}), tok)); err != nil {
		t.Fatalf("add to group: %v", err)
	}
	if _, err := cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: ownerID, Kind: "standing", ScopeFolderId: prod, SubjectGroupId: sre.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("binding: %v", err)
	}

	// admin explains alice: holds via prod folder binding.
	exp, err := cat.ExplainRole(ctx, withToken(connect.NewRequest(&catalogv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !exp.Msg.Holds {
		t.Fatal("expected holds=true")
	}
	if len(exp.Msg.Paths) == 0 {
		t.Fatal("expected at least one path")
	}
	p := exp.Msg.Paths[0]
	if len(p.Steps) == 0 {
		t.Fatal("expected non-empty steps")
	}
	if p.Subject != "group:"+sre.Msg.Group.Id {
		t.Fatalf("subject = %q, want group:%s", p.Subject, sre.Msg.Group.Id)
	}
	// path ends at the prod folder goal that the binding satisfies.
	last := p.Steps[len(p.Steps)-1]
	if last.ObjectKind != "folder" || last.ObjectId != prod || last.RoleId != ownerID {
		t.Fatalf("last step = %+v, want owner@folder:prod", last)
	}
	if p.BindingId == "" {
		t.Fatal("expected binding id")
	}

	// multi-path: add a SECOND, distinct derivation — a direct standing binding of
	// owner on the asset itself (subject = alice). She now holds owner@pg via both
	// the prod folder-cascade path and this direct-on-asset path.
	if _, err := cat.CreateRoleBinding(ctx, withToken(connect.NewRequest(&catalogv1.CreateRoleBindingRequest{
		RoleId: ownerID, Kind: "standing", ScopeAssetId: pgID, SubjectUserId: aliceID,
	}), tok)); err != nil {
		t.Fatalf("direct asset binding: %v", err)
	}
	multiExp, err := cat.ExplainRole(ctx, withToken(connect.NewRequest(&catalogv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain multi: %v", err)
	}
	if !multiExp.Msg.Holds {
		t.Fatal("expected holds=true with two derivations")
	}
	if len(multiExp.Msg.Paths) < 2 {
		t.Fatalf("expected >= 2 paths via two derivations, got %d", len(multiExp.Msg.Paths))
	}

	// negative: bob has no path.
	bob, err := id.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{Email: "bob@x", DisplayName: "Bob", Password: "password123"}), tok))
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	nexp, err := cat.ExplainRole(ctx, withToken(connect.NewRequest(&catalogv1.ExplainRoleRequest{
		UserId: bob.Msg.User.Id, RoleId: ownerID, AssetId: pgID,
	}), tok))
	if err != nil {
		t.Fatalf("explain bob: %v", err)
	}
	if nexp.Msg.Holds || len(nexp.Msg.Paths) != 0 {
		t.Fatalf("bob holds=%v paths=%d, want false/0", nexp.Msg.Holds, len(nexp.Msg.Paths))
	}

	// non-admin explaining ANOTHER user → PermissionDenied.
	atok := authClient(t, url, "alice@x", "password123")
	_, err = cat.ExplainRole(ctx, withToken(connect.NewRequest(&catalogv1.ExplainRoleRequest{
		UserId: bob.Msg.User.Id, RoleId: ownerID, AssetId: pgID,
	}), atok))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("alice explains bob = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// non-admin explaining THEMSELVES → allowed.
	selfExp, err := cat.ExplainRole(ctx, withToken(connect.NewRequest(&catalogv1.ExplainRoleRequest{
		UserId: aliceID, RoleId: ownerID, AssetId: pgID,
	}), atok))
	if err != nil {
		t.Fatalf("alice explains self: %v", err)
	}
	if !selfExp.Msg.Holds {
		t.Fatal("alice self-explain: expected holds=true")
	}
}
