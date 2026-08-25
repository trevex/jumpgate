package authz

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)
	rr := NewRoleResolver(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "deact-standing@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "deact-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "deact-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "deact-role", pgtype.UUID{}, caps("ssh:login:deploy"))
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "deact-group@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "deact-grp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: grp.ID, MemberUserID: pgUUID(user.ID)}); err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "deact-grp-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "deact-grp-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "deact-grp-role", pgtype.UUID{}, caps("db:read"))
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
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

// TestDeactivatedUserExplicitRequesterSubject proves the guard also zeroes the
// requestable tier reached purely through an explicit kind='requester' subject
// entry on a request policy: while active the role is requestable on the asset
// (visible via RolesOnAsset and VisibleAssets), once deactivated it disappears —
// a deactivated user is not an eligible requester even when named explicitly.
func TestDeactivatedUserExplicitRequesterSubject(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "deact-requester@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "deact-req-folder"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "deact-req-asset", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	role := createRoleWithCaps(t, ctx, q, "deact-req-role", pgtype.UUID{}, caps("db:read"))
	// Role-default request policy for the role, with NO requester_role — the only
	// path to eligibility is the explicit requester subject below.
	policy, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            role.ID,
		RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:      policy.ID,
		Kind:          "requester",
		SubjectUserID: pgUUID(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// While active: the role is requestable on the asset (both single-asset and
	// all-assets tiers).
	roles, err := a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatalf("active: RolesOnAsset error: %v", err)
	}
	if !containsRole(roles.Requestable, role.ID) {
		t.Fatalf("active: RolesOnAsset.Requestable = %v; want to contain %v", roles.Requestable, role.ID)
	}
	if !assetRequestable(t, a, user.ID, asset.ID, role.ID) {
		t.Fatal("active: asset must be requestable in VisibleAssets")
	}

	// Deactivate: the explicit requester subject must no longer make the role
	// requestable.
	deactivateUser(t, pool, user.ID)

	roles, err = a.RolesOnAsset(ctx, user.ID, asset.ID)
	if err != nil {
		t.Fatalf("deactivated: RolesOnAsset error: %v", err)
	}
	if containsRole(roles.Requestable, role.ID) {
		t.Fatalf("deactivated: RolesOnAsset.Requestable = %v; want NOT to contain %v", roles.Requestable, role.ID)
	}
	if assetRequestable(t, a, user.ID, asset.ID, role.ID) {
		t.Fatal("deactivated: asset must NOT be requestable in VisibleAssets")
	}
}

// containsRole reports whether roleID appears in the slice.
func containsRole(roles []uuid.UUID, roleID uuid.UUID) bool {
	for _, r := range roles {
		if r == roleID {
			return true
		}
	}
	return false
}

// assetRequestable reports whether (asset, role) appears as a requestable pair in
// the user's VisibleAssets (i.e. the asset is listed with the role among RoleIDs).
func assetRequestable(t *testing.T, a Authorizer, user, asset, role uuid.UUID) bool {
	t.Helper()
	vis, err := a.VisibleAssets(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vis {
		if v.AssetID == asset {
			return containsRole(v.RoleIDs, role)
		}
	}
	return false
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
