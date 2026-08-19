package authz

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// deactivateUser marks a user deactivated directly in the store.
func deactivateUser(t *testing.T, pool *pgxpool.Pool, user uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET deactivated_at = now() WHERE id = $1`, user); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
}

// TestDeactivatedUserStandingBinding proves the governing principle for a standing
// role_binding: while active the user is authorized on the asset; once deactivated
// every authorization query returns nothing — Check is false, EntitledLogins is
// empty, the asset is no longer active in VisibleAssets, and both HoldsRole and
// HoldsRoleStanding report false.
func TestDeactivatedUserStandingBinding(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)
	rr := NewRoleResolver(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "deact-standing@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "deact-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "deact-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "deact-role", ResourceType: "asset", Capabilities: caps("ssh:login:deploy")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgUUID(asset.ID), SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// While active: authorized everywhere.
	if ok, err := a.Check(ctx, user.ID, asset.ID, "ssh:login:deploy"); err != nil || !ok {
		t.Fatalf("active: Check = %v, %v; want true", ok, err)
	}
	logins, err := EntitledLogins(ctx, a, user.ID, asset.ID, []string{"deploy"})
	if err != nil || len(logins) != 1 || logins[0] != "deploy" {
		t.Fatalf("active: EntitledLogins = %v, %v; want [deploy]", logins, err)
	}
	if !assetActive(t, a, user.ID, asset.ID) {
		t.Fatal("active: asset must be visible+active")
	}
	if ok, err := rr.HoldsRole(ctx, user.ID, role.ID, "asset", asset.ID); err != nil || !ok {
		t.Fatalf("active: HoldsRole = %v, %v; want true", ok, err)
	}
	if ok, err := rr.HoldsRoleStanding(ctx, user.ID, role.ID, "asset", asset.ID); err != nil || !ok {
		t.Fatalf("active: HoldsRoleStanding = %v, %v; want true", ok, err)
	}

	// Deactivate: every authorization query must now return nothing.
	deactivateUser(t, pool, user.ID)

	if ok, err := a.Check(ctx, user.ID, asset.ID, "ssh:login:deploy"); err != nil || ok {
		t.Fatalf("deactivated: Check = %v, %v; want false", ok, err)
	}
	logins, err = EntitledLogins(ctx, a, user.ID, asset.ID, []string{"deploy"})
	if err != nil || len(logins) != 0 {
		t.Fatalf("deactivated: EntitledLogins = %v, %v; want empty", logins, err)
	}
	if assetActive(t, a, user.ID, asset.ID) {
		t.Fatal("deactivated: asset must NOT be active")
	}
	if ok, err := rr.HoldsRole(ctx, user.ID, role.ID, "asset", asset.ID); err != nil || ok {
		t.Fatalf("deactivated: HoldsRole = %v, %v; want false", ok, err)
	}
	if ok, err := rr.HoldsRoleStanding(ctx, user.ID, role.ID, "asset", asset.ID); err != nil || ok {
		t.Fatalf("deactivated: HoldsRoleStanding = %v, %v; want false", ok, err)
	}
}

// TestDeactivatedUserGroupBinding proves the guard also zeroes a login derived
// purely through group membership: the binding is on a group the user belongs to.
func TestDeactivatedUserGroupBinding(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "deact-group@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, "deact-grp")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "deact-grp-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "deact-grp-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "deact-grp-role", ResourceType: "asset", Capabilities: caps("db:read")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgUUID(asset.ID), SubjectGroupID: pgUUID(grp.ID),
	}); err != nil {
		t.Fatal(err)
	}

	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:read"); err != nil || !ok {
		t.Fatalf("active (group): Check = %v, %v; want true", ok, err)
	}

	deactivateUser(t, pool, user.ID)

	if ok, err := a.Check(ctx, user.ID, asset.ID, "db:read"); err != nil || ok {
		t.Fatalf("deactivated (group): Check = %v, %v; want false", ok, err)
	}
}

// TestDeactivatedUserActiveGrant proves the guard also zeroes access conferred by a
// non-expired JIT access_grant: the grant confers while active, nothing once the
// user is deactivated.
func TestDeactivatedUserActiveGrant(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	alice, _, _, pgstaging, _, _, _, dbaRole := seed(t, pool)
	a := NewSQLAuthorizer(pool)

	fabricateGrant(t, pool, alice, dbaRole, pgstaging, grantOpts{expiresIn: time.Hour})

	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || !ok {
		t.Fatalf("active (grant): Check(db:admin) = %v, %v; want true", ok, err)
	}

	deactivateUser(t, pool, alice)

	if ok, err := a.Check(ctx, alice, pgstaging, "db:admin"); err != nil || ok {
		t.Fatalf("deactivated (grant): Check(db:admin) = %v, %v; want false", ok, err)
	}
}

// assetActive reports whether the asset appears as Active in the user's
// VisibleAssets.
func assetActive(t *testing.T, a Authorizer, user, asset uuid.UUID) bool {
	t.Helper()
	vis, err := a.VisibleAssets(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vis {
		if v.AssetID == asset {
			return v.Active
		}
	}
	return false
}
