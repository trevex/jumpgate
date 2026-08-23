package authz

import (
	"context"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// TestMgmtScopeFolders: a user holding a management-cap role bound at a nested
// folder anchors that folder; a user holding only a connect (ssh) cap there does
// not.
func TestMgmtScopeFolders(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := &sqlAuthorizer{pool: pool}
	q := gen.New(pool)

	root := mustCreateFolder(t, q, "ma-root", nil)
	nested := mustCreateFolder(t, q, "ma-nested", &root)

	mgr := mustCreateUser(t, q, "ma-mgr@t")
	conn := mustCreateUser(t, q, "ma-conn@t")

	// mgr: a role carrying catalog:asset:read bound at the nested folder.
	mgrRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "ma-mgr-role", Capabilities: caps("catalog:asset:read"),
	})
	mustNoErr(t, err)
	_, err = q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: mgrRole.ID, ScopeFolderID: pgUUID(nested), SubjectUserID: pgUUID(mgr),
	})
	mustNoErr(t, err)

	// conn: a role carrying only ssh:login:* bound at the same nested folder.
	connRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "ma-conn-role", Capabilities: caps("ssh:login:*"),
	})
	mustNoErr(t, err)
	_, err = q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: connRole.ID, ScopeFolderID: pgUUID(nested), SubjectUserID: pgUUID(conn),
	})
	mustNoErr(t, err)

	mgrFolders, err := s.mgmtScopeFolders(ctx, mgr)
	mustNoErr(t, err)
	requireContains(t, keys(mgrFolders), nested)

	connFolders, err := s.mgmtScopeFolders(ctx, conn)
	mustNoErr(t, err)
	requireNotContains(t, keys(connFolders), nested)
}

// TestIsManagementCap covers the glob/prefix classification.
func TestIsManagementCap(t *testing.T) {
	mgmt := []string{"**", "*", "catalog:asset:read", "access:role:read", "identity:group:read", "catalog:folder:update"}
	connect := []string{"ssh:login:*", "ssh:connect", "ssh:record:exempt", "ssh:login:root"}
	for _, p := range mgmt {
		if !isManagementCap(p) {
			t.Errorf("expected %q to be a management cap", p)
		}
	}
	for _, p := range connect {
		if isManagementCap(p) {
			t.Errorf("expected %q NOT to be a management cap", p)
		}
	}
}

// TestVisibleNodeHomeAnchors: a role/group homed in a nested folder the user has
// an access relationship to anchors that folder.
func TestVisibleNodeHomeAnchors(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := &sqlAuthorizer{pool: pool}
	q := gen.New(pool)

	root := mustCreateFolder(t, q, "an-root", nil)
	nested := mustCreateFolder(t, q, "an-nested", &root)

	holder := mustCreateUser(t, q, "an-holder@t")
	member := mustCreateUser(t, q, "an-member@t")

	// A role homed @nested that the holder HOLDS (standing binding of that role).
	frole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "an-frole", FolderID: pgUUID(nested), Capabilities: caps("ssh:connect"),
	})
	mustNoErr(t, err)
	_, err = q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: frole.ID, ScopeFolderID: pgUUID(nested), SubjectUserID: pgUUID(holder),
	})
	mustNoErr(t, err)

	roleFolders, err := s.visibleRoleHomeFolders(ctx, holder)
	mustNoErr(t, err)
	requireContains(t, keys(roleFolders), nested)

	// A group homed @nested that member is a member of.
	fgroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "an-fgroup", FolderID: pgUUID(nested)})
	mustNoErr(t, err)
	err = q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: fgroup.ID, MemberUserID: pgUUID(member)})
	mustNoErr(t, err)

	groupFolders, err := s.visibleGroupHomeFolders(ctx, member)
	mustNoErr(t, err)
	requireContains(t, keys(groupFolders), nested)

	// The holder (not a member) does not anchor the group's home folder via groups.
	holderGroupFolders, err := s.visibleGroupHomeFolders(ctx, holder)
	mustNoErr(t, err)
	requireNotContains(t, keys(holderGroupFolders), nested)
}

// TestVisibleAssetFolders: an asset the user is connect-visible on anchors its
// home folder.
func TestVisibleAssetFolders(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := &sqlAuthorizer{pool: pool}
	q := gen.New(pool)

	root := mustCreateFolder(t, q, "af-root", nil)
	nested := mustCreateFolder(t, q, "af-nested", &root)

	user := mustCreateUser(t, q, "af-user@t")
	stranger := mustCreateUser(t, q, "af-stranger@t")

	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{
		FolderID: nested, Name: "af-asset", Labels: []byte("{}"), Kind: "ssh",
	})
	mustNoErr(t, err)
	// A ca login on the asset (no secret required for kind=ca).
	_, err = q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "root", Kind: "ca",
	})
	mustNoErr(t, err)

	// user: a role entitling ssh:login:root bound at the nested folder ⇒ the asset
	// is connect-visible, so its folder anchors.
	connRole, err := q.CreateRole(ctx, gen.CreateRoleParams{
		Name: "af-conn-role", Capabilities: caps("ssh:login:root"),
	})
	mustNoErr(t, err)
	_, err = q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: connRole.ID, ScopeFolderID: pgUUID(nested), SubjectUserID: pgUUID(user),
	})
	mustNoErr(t, err)

	folders, err := s.visibleAssetFolders(ctx, user)
	mustNoErr(t, err)
	requireContains(t, keys(folders), nested)

	// stranger sees nothing.
	strangerFolders, err := s.visibleAssetFolders(ctx, stranger)
	mustNoErr(t, err)
	requireNotContains(t, keys(strangerFolders), nested)
}
