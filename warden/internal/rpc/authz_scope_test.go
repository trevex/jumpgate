package rpc_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// seedCapUserScoped creates a non-admin user bound to a fresh role carrying
// capsJSON at a specific scope: a folder (scopeFolder set), an asset (scopeAsset
// set), or global (both uuid.Nil). It returns the user id. Unlike seedCapUser
// (which binds globally), this pins the binding scope so scope-boundary
// enforcement can be exercised.
func seedCapUserScoped(t *testing.T, pool *pgxpool.Pool, email, pw, capsJSON string, scopeFolder, scopeAsset uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "role-"+uuid.NewString(), pgtype.UUID{}, capsJSON)
	params := gen.CreateRoleBindingParams{RoleID: role.ID, SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true}}
	if scopeFolder != uuid.Nil {
		params.ScopeFolderID = pgtype.UUID{Bytes: scopeFolder, Valid: true}
	}
	if scopeAsset != uuid.Nil {
		params.ScopeAssetID = pgtype.UUID{Bytes: scopeAsset, Valid: true}
	}
	if _, err := q.CreateRoleBinding(ctx, params); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// twoFolder builds two sibling top-level folders A and B, each with one ssh asset,
// as the admin. It returns their ids/paths.
type twoFolder struct {
	folderA, folderB string
	assetA, assetB   string
	pathA, pathB     string
}

func setupTwoFolders(t *testing.T, url, adminTok string) twoFolder {
	t.Helper()
	ctx := context.Background()
	cat := newGuardClients(url).catalog
	mk := func(fname, aname string) (string, string, string) {
		f, err := cat.CreateFolder(ctx, withToken(connect.NewRequest(&catalogv1.CreateFolderRequest{Name: fname}), adminTok))
		if err != nil {
			t.Fatalf("folder %s: %v", fname, err)
		}
		a, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: f.Msg.Folder.Id, Name: aname, Config: emptySSHConfig()}), adminTok))
		if err != nil {
			t.Fatalf("asset %s: %v", aname, err)
		}
		return f.Msg.Folder.Id, a.Msg.Asset.Id, a.Msg.Asset.Path
	}
	var tf twoFolder
	tf.folderA, tf.assetA, tf.pathA = mk("team-a", "box-a")
	tf.folderB, tf.assetB, tf.pathB = mk("team-b", "box-b")
	return tf
}

// TestAuthzFolderScopeIsolation proves a folder-scoped management capability does
// NOT reach a sibling folder. A user holding catalog:asset:{read,create} at
// team-a can read/list/create there, but every equivalent operation against
// team-b is denied — capability held at A never leaks to its sibling B.
func TestAuthzFolderScopeIsolation(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	adminTok := adminToken(t, url)
	tf := setupTwoFolders(t, url, adminTok)

	folderAUUID := uuid.MustParse(tf.folderA)
	seedCapUserScoped(t, pool, "a-admin@x", "password123", `["catalog:asset:read","catalog:asset:create"]`, folderAUUID, uuid.Nil)
	tok := authClient(t, url, "a-admin@x", "password123")
	cat := newGuardClients(url).catalog
	ctx := context.Background()

	// Allowed within team-a.
	if _, err := cat.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: tf.assetA}), tok)); err != nil {
		t.Fatalf("GetAsset(A) should succeed: %v", err)
	}
	if la, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: tf.folderA}), tok)); err != nil {
		t.Fatalf("ListAssets(A) should succeed: %v", err)
	} else if len(la.Msg.Assets) == 0 {
		t.Fatalf("ListAssets(A) should list team-a's manageable asset, got none")
	}
	if _, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: tf.folderA, Name: "box-a2", Config: emptySSHConfig()}), tok)); err != nil {
		t.Fatalf("CreateAsset(A) should succeed: %v", err)
	}

	// Denied against sibling team-b.
	if _, err := cat.GetAsset(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: tf.assetB}), tok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("GetAsset(B) = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// ListAssets is not cap-gated; it is visibility-filtered and existence-hiding.
	// The A-admin has no relationship to sibling B, so browsing B returns NotFound
	// (never PermissionDenied — B's existence stays hidden), same as ResolveAsset.
	if _, err := cat.ListAssets(ctx, withToken(connect.NewRequest(&catalogv1.ListAssetsRequest{Parent: tf.folderB}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("ListAssets(B) = %v, want NotFound (existence hiding)", connect.CodeOf(err))
	}
	if _, err := cat.CreateAsset(ctx, withToken(connect.NewRequest(&catalogv1.CreateAssetRequest{FolderId: tf.folderB, Name: "box-b2", Config: emptySSHConfig()}), tok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("CreateAsset(B) = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// ResolveAsset is existence-hiding: the A-admin resolves A's asset by path but
	// gets NotFound for B's asset (never PermissionDenied — B stays invisible).
	if _, err := cat.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: tf.pathA}), tok)); err != nil {
		t.Errorf("ResolveAsset(A) should succeed: %v", err)
	}
	if _, err := cat.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: tf.pathB}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("ResolveAsset(B) = %v, want NotFound (existence hiding)", connect.CodeOf(err))
	}
}

// TestAuthzObjectDerivedScope proves that for object-scoped mutations the guard is
// checked at the SCOPE OF THE TARGET OBJECT, not merely "somewhere". A user
// holding a capability at team-a can act on team-a objects but is denied on the
// identically-typed team-b object.
func TestAuthzObjectDerivedScope(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	adminTok := adminToken(t, url)
	tf := setupTwoFolders(t, url, adminTok)
	acc := newGuardClients(url).access
	vault := newGuardClients(url).vault
	ctx := context.Background()

	// A deletable role-binding in each folder (a global role bound at each folder).
	q := gen.New(pool)
	role := createRoleWithCaps(t, ctx, q, "r-"+uuid.NewString(), pgtype.UUID{}, `["ssh:login:deploy"]`)
	grp, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "g-" + uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	mkBinding := func(folderID string) string {
		b, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: role.ID, ScopeFolderID: pgtype.UUID{Bytes: uuid.MustParse(folderID), Valid: true},
			SubjectGroupID: pgtype.UUID{Bytes: grp.ID, Valid: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b.ID.String()
	}
	bindingA := mkBinding(tf.folderA)
	bindingB := mkBinding(tf.folderB)

	// A secret on each asset.
	admSetSecret := func(assetID string) string {
		if _, err := vault.SetAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.SetAssetSecretRequest{AssetId: assetID, Name: "s", Value: []byte("v")}), adminTok)); err != nil {
			t.Fatal(err)
		}
		list, err := vault.ListAssetSecrets(ctx, withToken(connect.NewRequest(&vaultv1.ListAssetSecretsRequest{AssetId: assetID}), adminTok))
		if err != nil || len(list.Msg.Secrets) == 0 {
			t.Fatal(err)
		}
		return list.Msg.Secrets[0].Id
	}
	secretA := admSetSecret(tf.assetA)
	secretB := admSetSecret(tf.assetB)

	// binding:delete holder at team-a: deletes the A binding, denied on the B binding.
	seedCapUserScoped(t, pool, "bd@x", "password123", `["access:binding:delete"]`, uuid.MustParse(tf.folderA), uuid.Nil)
	bdTok := authClient(t, url, "bd@x", "password123")
	if _, err := acc.DeleteRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: bindingB}), bdTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("DeleteRoleBinding(B) = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := acc.DeleteRoleBinding(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: bindingA}), bdTok)); err != nil {
		t.Errorf("DeleteRoleBinding(A) should succeed: %v", err)
	}

	// secret:write holder at asset-a: writes/deletes A's secret, denied on B's.
	seedCapUserScoped(t, pool, "sw@x", "password123", `["vault:secret:write"]`, uuid.Nil, uuid.MustParse(tf.assetA))
	swTok := authClient(t, url, "sw@x", "password123")
	if _, err := vault.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: secretB}), swTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("DeleteAssetSecret(B) = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := vault.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: secretA}), swTok)); err != nil {
		t.Errorf("DeleteAssetSecret(A) should succeed: %v", err)
	}
}

// TestAuthzMissingObjectFailsClosed proves the "cannot derive scope → require the
// GLOBAL capability" fallback on the delete-by-id endpoints. A folder-scoped
// holder cannot use a nonexistent id to slip past scope enforcement: the fallback
// demands a global capability the holder does not have, so it is denied — the
// same code a real cross-scope object would produce, leaking nothing.
func TestAuthzMissingObjectFailsClosed(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	adminTok := adminToken(t, url)
	tf := setupTwoFolders(t, url, adminTok)
	acc := newGuardClients(url).access
	vault := newGuardClients(url).vault
	ctx := context.Background()
	missing := uuid.NewString()

	// Folder-scoped access:role:update holder → RemoveRoleGrant of a nonexistent
	// edge requires the global cap (scope cannot be derived) → PermissionDenied.
	seedCapUserScoped(t, pool, "ru@x", "password123", `["access:role:update"]`, uuid.MustParse(tf.folderA), uuid.Nil)
	ruTok := authClient(t, url, "ru@x", "password123")
	if _, err := acc.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.RemoveRoleGrantRequest{Id: missing}), ruTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("RemoveRoleGrant(missing) as folder-scoped = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Asset-scoped vault:secret:write holder → DeleteAssetSecret of a nonexistent
	// secret likewise requires the global cap → PermissionDenied.
	seedCapUserScoped(t, pool, "sw2@x", "password123", `["vault:secret:write"]`, uuid.Nil, uuid.MustParse(tf.assetA))
	sw2Tok := authClient(t, url, "sw2@x", "password123")
	if _, err := vault.DeleteAssetSecret(ctx, withToken(connect.NewRequest(&vaultv1.DeleteAssetSecretRequest{Id: missing}), sw2Tok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("DeleteAssetSecret(missing) as asset-scoped = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// The bootstrap admin (** globally) treats the same missing ids as a NotFound /
	// no-op, confirming the fallback gates on capability, not on existence.
	if _, err := acc.RemoveRoleGrant(ctx, withToken(connect.NewRequest(&accessv1.RemoveRoleGrantRequest{Id: missing}), adminTok)); err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("RemoveRoleGrant(missing) as admin = %v, want ok or NotFound", connect.CodeOf(err))
	}
}
