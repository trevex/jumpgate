package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// TestConnCascade pins the data-plane connect cascade over real Postgres:
// ConnectCapabilities(user, asset).EntitledLogins(...) resolves an ssh:login:<x>
// binding held on an ANCESTOR FOLDER, on the ASSET, or GLOBALLY — the same scope
// cascade as management — while the literal `**` super-capability held globally
// confers NO connect (the carve-out), and a sibling-folder binding does not reach.
func TestConnCascade(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	a := NewSQLAuthorizer(pool).(*sqlAuthorizer)

	// Roles: a concrete ssh:login:deploy role and the `**` super-role.
	deployRole := createRoleWithCaps(t, ctx, q, "cc-deploy", pgtype.UUID{}, caps("ssh:login:deploy"))
	starRole := createRoleWithCaps(t, ctx, q, "cc-star", pgtype.UUID{}, caps("**"))

	// Tree: folder F ⊃ asset A ; sibling folder G.
	folderF, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "cc-f"})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "cc-sib"})
	if err != nil {
		t.Fatal(err)
	}
	assetA, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folderF.ID, Name: "cc-a", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	entitled := func(t *testing.T, userID uuid.UUID) []string {
		t.Helper()
		c, err := ConnectCapabilities(ctx, a, userID, assetA.ID)
		if err != nil {
			t.Fatalf("ConnectCapabilities: %v", err)
		}
		return c.EntitledLogins([]string{"deploy"})
	}

	mkUser := func(t *testing.T, email string) uuid.UUID {
		t.Helper()
		u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: email, DisplayName: email})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}

	// --- folder-scoped ssh:login:deploy → entitled on the asset under F (NEW) ---
	folderUser := mkUser(t, "cc-folder@x")
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: deployRole.ID, ScopeFolderID: pgUUID(folderF.ID), SubjectUserID: pgUUID(folderUser),
	}); err != nil {
		t.Fatal(err)
	}
	if got := entitled(t, folderUser); len(got) != 1 || got[0] != "deploy" {
		t.Fatalf("folder-scoped binding must confer connect on child asset; got %v want [deploy]", got)
	}

	// --- same role bound on the SIBLING folder → NOT entitled on the asset ---
	sibUser := mkUser(t, "cc-sib@x")
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: deployRole.ID, ScopeFolderID: pgUUID(sibling.ID), SubjectUserID: pgUUID(sibUser),
	}); err != nil {
		t.Fatal(err)
	}
	if got := entitled(t, sibUser); got != nil {
		t.Fatalf("sibling-folder binding must not reach the asset; got %v want nil", got)
	}

	// --- `**` bound GLOBALLY → NOT entitled (the carve-out) ---
	starUser := mkUser(t, "cc-star@x")
	insertGlobalBinding(t, pool, starRole.ID, starUser)
	if got := entitled(t, starUser); got != nil {
		t.Fatalf("global ** must NOT confer connect; got %v want nil", got)
	}

	// --- ssh:login:deploy bound on the ASSET → entitled (regression) ---
	assetUser := mkUser(t, "cc-asset@x")
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: deployRole.ID, ScopeAssetID: pgUUID(assetA.ID), SubjectUserID: pgUUID(assetUser),
	}); err != nil {
		t.Fatal(err)
	}
	if got := entitled(t, assetUser); len(got) != 1 || got[0] != "deploy" {
		t.Fatalf("asset-scoped binding must confer connect; got %v want [deploy]", got)
	}

	// --- `**` bound on the ASSET → NOT entitled (carve-out at object scope too) ---
	starAssetUser := mkUser(t, "cc-star-a@x")
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: starRole.ID, ScopeAssetID: pgUUID(assetA.ID), SubjectUserID: pgUUID(starAssetUser),
	}); err != nil {
		t.Fatal(err)
	}
	if got := entitled(t, starAssetUser); got != nil {
		t.Fatalf("asset-scoped ** must NOT confer connect; got %v want nil", got)
	}
}
