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

// expectNotify waits up to 2s for a notification on the listening conn and returns
// its payload.
func expectNotify(t *testing.T, conn *pgxpool.Conn, what string) string {
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
	return n.Payload
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
	role, err := createRoleCaps(ctx, q, "db_admin")
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

	// DELETE of the role_binding revokes standing authz → must notify. Because the
	// binding's subject is a single user, the payload narrows to that user's id.
	if err := q.DeleteRoleBinding(ctx, binding.ID); err != nil {
		t.Fatalf("DeleteRoleBinding: %v", err)
	}
	if got := expectNotify(t, conn, "role_bindings DELETE"); got != user.ID.String() {
		t.Fatalf("role_bindings DELETE payload = %q, want user id %q", got, user.ID)
	}

	// A second table sharing the function: UPDATE users fires too (e.g. a user
	// deactivation flips standing eligibility). The payload is that user's id.
	if _, err := pool.Exec(ctx, `UPDATE users SET display_name = $1 WHERE id = $2`, "renamed", user.ID); err != nil {
		t.Fatalf("UPDATE users: %v", err)
	}
	if got := expectNotify(t, conn, "users UPDATE"); got != user.ID.String() {
		t.Fatalf("users UPDATE payload = %q, want user id %q", got, user.ID)
	}
}

// TestAuthzChangedPayloadNarrows exercises the subject-narrowing contract of the
// authz_changed trigger: single-user changes carry the user id (narrowed sweep);
// transitive changes (group-subject bindings, nested group memberships, role rewrites,
// role-grant edges) carry an empty payload (full sweep). Empty is always safe.
func TestAuthzChangedPayloadNarrows(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	role, err := createRoleCaps(ctx, q, "r-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "f-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "a", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	user, err := q.CreateUser(ctx, gen.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	group, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "g-" + uuid.NewString(), FolderID: pg(folder.ID)})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	nested, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "g2-" + uuid.NewString(), FolderID: pg(folder.ID)})
	if err != nil {
		t.Fatalf("CreateGroup nested: %v", err)
	}

	conn := listen(t, pool)

	// (1) A GROUP-subject binding delete is transitive → empty payload (full sweep).
	gBinding, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pg(asset.ID), SubjectGroupID: pg(group.ID),
	})
	if err != nil {
		t.Fatalf("CreateRoleBinding (group): %v", err)
	}
	if err := q.DeleteRoleBinding(ctx, gBinding.ID); err != nil {
		t.Fatalf("DeleteRoleBinding (group): %v", err)
	}
	if got := expectNotify(t, conn, "group-subject binding DELETE"); got != "" {
		t.Fatalf("group-subject binding DELETE payload = %q, want empty (full sweep)", got)
	}

	// (2) A direct USER group membership delete narrows to that user.
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships (group_id, member_user_id) VALUES ($1, $2)`, group.ID, user.ID); err != nil {
		t.Fatalf("insert user membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_memberships WHERE group_id = $1 AND member_user_id = $2`, group.ID, user.ID); err != nil {
		t.Fatalf("delete user membership: %v", err)
	}
	if got := expectNotify(t, conn, "user membership DELETE"); got != user.ID.String() {
		t.Fatalf("user membership DELETE payload = %q, want user id %q", got, user.ID)
	}

	// (3) A NESTED group membership delete is transitive → empty payload (full sweep).
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships (group_id, member_group_id) VALUES ($1, $2)`, group.ID, nested.ID); err != nil {
		t.Fatalf("insert nested membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_memberships WHERE group_id = $1 AND member_group_id = $2`, group.ID, nested.ID); err != nil {
		t.Fatalf("delete nested membership: %v", err)
	}
	if got := expectNotify(t, conn, "nested membership DELETE"); got != "" {
		t.Fatalf("nested membership DELETE payload = %q, want empty (full sweep)", got)
	}

	// (4) A role_grants edge change is transitive (affects all holders) → empty payload.
	srcRole, err := createRoleCaps(ctx, q, "src-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateRole src: %v", err)
	}
	grant, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: role.ID, SourceRoleID: srcRole.ID, Via: "same_object"})
	if err != nil {
		t.Fatalf("CreateRoleGrant: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM role_grants WHERE role_id = $1 AND source_role_id = $2`, grant.RoleID, grant.SourceRoleID); err != nil {
		t.Fatalf("delete role grant: %v", err)
	}
	if got := expectNotify(t, conn, "role_grants DELETE"); got != "" {
		t.Fatalf("role_grants DELETE payload = %q, want empty (full sweep)", got)
	}

	// (5) A roles rewrite is transitive (affects all holders) → empty payload.
	if _, err := pool.Exec(ctx, `UPDATE roles SET name = $1 WHERE id = $2`, "db_admin-renamed", role.ID); err != nil {
		t.Fatalf("UPDATE roles: %v", err)
	}
	if got := expectNotify(t, conn, "roles UPDATE"); got != "" {
		t.Fatalf("roles UPDATE payload = %q, want empty (full sweep)", got)
	}
}
