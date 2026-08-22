package rpc_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

// strptr returns a pointer to s, for the optional (oneof-presence) proto fields on
// the Update requests.
func strptr(s string) *string { return &s }

// createFolderScopedRole inserts a folder-homed role (empty capabilities) and
// returns its id. A binding/policy granting this role is only valid while its scope
// lies within folderID's subtree — the containment invariant a move must preserve.
func (e *catalogTestEnv) createFolderScopedRole(t *testing.T, name, folderID string) string {
	t.Helper()
	var roleID string
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO roles(name, capabilities, folder_id) VALUES($1, '[]', $2) RETURNING id`,
		name, folderID,
	).Scan(&roleID); err != nil {
		t.Fatalf("insert folder-scoped role: %v", err)
	}
	return roleID
}

// bindRoleToAssetScoped inserts a standing role_binding of roleID scoped to assetID
// with the seeded admin as subject.
func (e *catalogTestEnv) bindRoleToAssetScoped(t *testing.T, roleID, assetID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO role_bindings(role_id, scope_asset_id, subject_user_id) VALUES($1, $2, $3)`,
		roleID, assetID, e.userID,
	); err != nil {
		t.Fatalf("insert role_binding: %v", err)
	}
}

// authzWaiter holds a dedicated LISTEN connection so the same backend session
// receives NOTIFY authz_changed committed by the server under test.
type authzWaiter struct {
	conn *pgxpool.Conn
}

// listenAuthzChanged checks out a pool connection and LISTENs on authz_changed;
// the conn is released on test cleanup.
func (e *catalogTestEnv) listenAuthzChanged(t *testing.T) *authzWaiter {
	t.Helper()
	conn, err := e.pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire listen conn: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "LISTEN authz_changed"); err != nil {
		conn.Release()
		t.Fatalf("LISTEN: %v", err)
	}
	t.Cleanup(conn.Release)
	return &authzWaiter{conn: conn}
}

// expectNotify waits up to 5s for an authz_changed notification.
func (w *authzWaiter) expectNotify(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n, err := w.conn.Conn().WaitForNotification(ctx)
	if err != nil {
		t.Fatalf("expected authz_changed notification, got err: %v", err)
	}
	if n.Channel != "authz_changed" {
		t.Fatalf("notification on channel %q, want authz_changed", n.Channel)
	}
}

func TestMoveAssetDeniedOnContainmentBreak(t *testing.T) {
	env := newCatalogTestEnv(t)
	home := env.createFolder(t, "team")
	other := env.createFolder(t, "other")
	assetID := env.createSSHAsset(t, home, "box", "app", []byte("pw"))
	roleID := env.createFolderScopedRole(t, "reader", home)
	env.bindRoleToAssetScoped(t, roleID, assetID) // valid: asset in home

	_, err := env.catalog.UpdateAsset(env.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetRequest{
		AssetId: assetID, FolderId: strptr(other),
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition (containment break), got %v", err)
	}
}

func TestMoveAssetAllowedFiresAuthzChanged(t *testing.T) {
	env := newCatalogTestEnv(t)
	src := env.createFolder(t, "src")
	dst := env.createFolder(t, "dst")
	assetID := env.createSSHAsset(t, src, "box", "app", []byte("pw"))

	waiter := env.listenAuthzChanged(t)
	if _, err := env.catalog.UpdateAsset(env.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetRequest{
		AssetId: assetID, FolderId: strptr(dst),
	})); err != nil {
		t.Fatalf("UpdateAsset move: %v", err)
	}
	waiter.expectNotify(t)
	got, _ := env.catalog.GetAsset(env.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID}))
	if got.Msg.Asset.Path != "box.dst" {
		t.Fatalf("path = %q, want box.dst", got.Msg.Asset.Path)
	}
}

func TestMoveFolderDeniedOnCycle(t *testing.T) {
	env := newCatalogTestEnv(t)
	parent := env.createFolder(t, "p")
	child := env.createChildFolder(t, "c", parent)
	_, err := env.catalog.UpdateFolder(env.adminCtx, connect.NewRequest(&catalogv1.UpdateFolderRequest{
		FolderId: parent, ParentId: strptr(child),
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition (cycle), got %v", err)
	}
}

func TestRenameFolderCollision(t *testing.T) {
	env := newCatalogTestEnv(t)
	env.createFolder(t, "a")
	b := env.createFolder(t, "b")
	_, err := env.catalog.UpdateFolder(env.adminCtx, connect.NewRequest(&catalogv1.UpdateFolderRequest{
		FolderId: b, Name: strptr("a"),
	}))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("want AlreadyExists (name collision), got %v", err)
	}
}

func TestRenameAssetSucceeds(t *testing.T) {
	env := newCatalogTestEnv(t)
	f := env.createFolder(t, "f")
	assetID := env.createSSHAsset(t, f, "old", "app", []byte("pw"))
	if _, err := env.catalog.UpdateAsset(env.adminCtx, connect.NewRequest(&catalogv1.UpdateAssetRequest{
		AssetId: assetID, Name: strptr("new"),
	})); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, _ := env.catalog.GetAsset(env.adminCtx, connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID}))
	if got.Msg.Asset.Name != "new" || got.Msg.Asset.Path != "new.f" {
		t.Fatalf("got name=%q path=%q, want new / new.f", got.Msg.Asset.Name, got.Msg.Asset.Path)
	}
}
