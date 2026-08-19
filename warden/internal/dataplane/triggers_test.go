package dataplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// listen acquires a dedicated pool connection and issues LISTEN authz_changed on
// it. The returned conn stays checked out for the caller's lifetime so that the
// same backend session receives NOTIFY delivered by other connections' commits.
func listen(t *testing.T, pool *pgxpool.Pool) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire listen conn: %v", err)
	}
	if _, err := conn.Exec(context.Background(), "LISTEN authz_changed"); err != nil {
		conn.Release()
		t.Fatalf("LISTEN: %v", err)
	}
	t.Cleanup(conn.Release)
	return conn
}

// expectNotify waits up to 2s for a notification on the listening conn.
func expectNotify(t *testing.T, conn *pgxpool.Conn, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := conn.Conn().WaitForNotification(ctx)
	if err != nil {
		t.Fatalf("%s: expected authz_changed notification, got err: %v", what, err)
	}
	if n.Channel != "authz_changed" {
		t.Fatalf("%s: notification on channel %q, want authz_changed", what, n.Channel)
	}
}

// expectNoNotify drains for ~300ms and fails if any notification arrives.
func expectNoNotify(t *testing.T, conn *pgxpool.Conn, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	n, err := conn.Conn().WaitForNotification(ctx)
	if err != nil {
		// A timeout (deadline exceeded) is the expected, healthy outcome.
		return
	}
	t.Fatalf("%s: unexpected notification on %q", what, n.Channel)
}

func TestAuthzChangedTriggerFires(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	// FK graph: a role, a folder+asset scope, and a user to bind.
	role, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "db_admin", ResourceType: "asset", Capabilities: capsJSON()})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	conn := listen(t, pool)

	// INSERT of a standing role_binding must NOT notify: only revoking writes do.
	binding, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pg(asset.ID), SubjectUserID: pg(user.ID),
	})
	if err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
	expectNoNotify(t, conn, "role_bindings INSERT")

	// DELETE of the role_binding revokes standing authz → must notify.
	if err := q.DeleteRoleBinding(ctx, binding.ID); err != nil {
		t.Fatalf("DeleteRoleBinding: %v", err)
	}
	expectNotify(t, conn, "role_bindings DELETE")

	// A second table sharing the function: UPDATE users fires too (e.g. a user
	// deactivation flips standing eligibility).
	if _, err := pool.Exec(ctx, `UPDATE users SET display_name = $1 WHERE id = $2`, "renamed", user.ID); err != nil {
		t.Fatalf("UPDATE users: %v", err)
	}
	expectNotify(t, conn, "users UPDATE")
}
