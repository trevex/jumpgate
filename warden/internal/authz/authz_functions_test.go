package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustSeedUser creates one active user and returns its id. Shared by the Phase 1
// parity tests. Uses *pgxpool.Pool to match the existing seeders in testhelpers_test.go.
func mustSeedUser(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users(email, display_name) VALUES($1,$1) RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return id
}

func TestActiveAccessGrantsView(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// Fresh DB: no grants yet -> the view exists and returns 0 rows without error.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM active_access_grants`).Scan(&count); err != nil {
		t.Fatalf("query view: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 active grants on fresh db, got %d", count)
	}

	// authz_user_is_active exists and rejects a non-existent user.
	var active bool
	if err := pool.QueryRow(ctx, `SELECT authz_user_is_active($1)`, uuid.New()).Scan(&active); err != nil {
		t.Fatalf("scalar: %v", err)
	}
	if active {
		t.Fatalf("random uuid must not be an active user")
	}

	// A freshly seeded (non-deactivated) user IS active.
	u := mustSeedUser(t, pool, "active-scalar@x")
	if err := pool.QueryRow(ctx, `SELECT authz_user_is_active($1)`, u).Scan(&active); err != nil {
		t.Fatalf("scalar seeded: %v", err)
	}
	if !active {
		t.Fatalf("freshly seeded user must be active")
	}
}

func TestAuthzUserGroupsParity(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	// Build a nested group membership chain: user -> ga -> gb.
	// NB: group names must satisfy the `^[a-z0-9_-]+$` check constraint.
	var user, gA, gB uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users(email,display_name) VALUES('u@x','u') RETURNING id`).Scan(&user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO groups(name) VALUES('ga') RETURNING id`).Scan(&gA); err != nil {
		t.Fatalf("seed ga: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO groups(name) VALUES('gb') RETURNING id`).Scan(&gB); err != nil {
		t.Fatalf("seed gb: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships(group_id, member_user_id) VALUES($1,$2)`, gA, user); err != nil {
		t.Fatalf("membership user->ga: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships(group_id, member_group_id) VALUES($1,$2)`, gB, gA); err != nil {
		t.Fatalf("membership ga->gb: %v", err)
	}

	// New function result.
	got := map[uuid.UUID]struct{}{}
	rows, err := pool.Query(ctx, `SELECT group_id FROM authz_user_groups($1)`, user)
	if err != nil {
		t.Fatalf("fn: %v", err)
	}
	for rows.Next() {
		var g uuid.UUID
		if err := rows.Scan(&g); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[g] = struct{}{}
	}
	rows.Close()

	// Expected: both gA and gB (transitive).
	if _, ok := got[gA]; !ok {
		t.Fatalf("missing gA")
	}
	if _, ok := got[gB]; !ok {
		t.Fatalf("missing gB (transitive)")
	}
	if len(got) != 2 {
		t.Fatalf("want 2 groups, got %d", len(got))
	}
}

// pgxNamed is a tiny helper: pgx.NamedArgs{"user": u}.
func pgxNamed(u uuid.UUID) pgx.NamedArgs { return pgx.NamedArgs{"user": u} }

func TestAuthzHeldParity(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	_, alice, _, _, _, _, a1, _ := seedTree(t, pool) // existing seeder

	// Old builder result (heldCTE is still present during migration).
	old := map[[2]string]struct{}{}
	rows, err := pool.Query(ctx, heldCTE+`
SELECT DISTINCT object_kind, object_id, role_id FROM held`, pgxNamed(alice))
	if err != nil {
		t.Fatalf("old: %v", err)
	}
	for rows.Next() {
		var k string
		var o, r uuid.UUID
		if err := rows.Scan(&k, &o, &r); err != nil {
			t.Fatalf("old scan: %v", err)
		}
		old[[2]string{k, o.String() + "|" + r.String()}] = struct{}{}
	}
	rows.Close()

	// New function result.
	neu := map[[2]string]struct{}{}
	rows2, err := pool.Query(ctx, `SELECT object_kind, object_id, role_id FROM authz_held($1)`, alice)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for rows2.Next() {
		var k string
		var o, r uuid.UUID
		if err := rows2.Scan(&k, &o, &r); err != nil {
			t.Fatalf("new scan: %v", err)
		}
		neu[[2]string{k, o.String() + "|" + r.String()}] = struct{}{}
	}
	rows2.Close()

	if len(old) != len(neu) {
		t.Fatalf("cardinality: old=%d new=%d", len(old), len(neu))
	}
	for k := range old {
		if _, ok := neu[k]; !ok {
			t.Fatalf("row in old missing from new: %v", k)
		}
	}
	_ = a1
}

// TestAuthzHeldStandingExcludesGrants pins the security invariant that a JIT
// access_grant confers access (authz_held) but NOT governance (authz_held_standing).
// A user with a standing binding on one role AND an active grant of a DIFFERENT
// role on the same asset must show BOTH roles in authz_held and ONLY the binding
// role in authz_held_standing.
func TestAuthzHeldStandingExcludesGrants(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	var user, folder, asset, bindingRole, grantRole, request uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users(email,display_name) VALUES('standing@x','standing') RETURNING id`).Scan(&user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO folders(name) VALUES('f') RETURNING id`).Scan(&folder); err != nil {
		t.Fatalf("seed folder: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO assets(name, folder_id) VALUES('a',$1) RETURNING id`, folder).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO roles(name) VALUES('binding-role') RETURNING id`).Scan(&bindingRole); err != nil {
		t.Fatalf("seed binding role: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO roles(name) VALUES('grant-role') RETURNING id`).Scan(&grantRole); err != nil {
		t.Fatalf("seed grant role: %v", err)
	}

	// (a) standing role_binding: bindingRole on the asset for the user.
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_bindings(role_id, scope_asset_id, subject_user_id) VALUES($1,$2,$3)`,
		bindingRole, asset, user); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// (b) an active (non-revoked, future-expiry) access_grant conferring grantRole on
	// the same asset. A grant requires a backing access_request (request_id is a
	// NOT NULL, UNIQUE FK).
	if err := pool.QueryRow(ctx, `
INSERT INTO access_requests(requester_user_id, role_id, asset_id, requested_duration, required_approvals, granted_duration, status)
VALUES($1,$2,$3,interval '1 hour',1,interval '1 hour','granted') RETURNING id`,
		user, grantRole, asset).Scan(&request); err != nil {
		t.Fatalf("seed request: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO access_grants(request_id, role_id, scope_asset_id, subject_user_id, expires_at)
VALUES($1,$2,$3,$4, now() + interval '1 hour')`,
		request, grantRole, asset, user); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	held := heldRoleSet(t, pool, `SELECT role_id FROM authz_held($1)`, user)
	standing := heldRoleSet(t, pool, `SELECT role_id FROM authz_held_standing($1)`, user)

	// authz_held (access): BOTH roles.
	if _, ok := held[bindingRole]; !ok {
		t.Fatalf("authz_held missing binding role %s", bindingRole)
	}
	if _, ok := held[grantRole]; !ok {
		t.Fatalf("authz_held missing granted role %s (grant confers access)", grantRole)
	}

	// authz_held_standing (governance): ONLY the binding role, NEVER the granted one.
	if _, ok := standing[bindingRole]; !ok {
		t.Fatalf("authz_held_standing missing binding role %s", bindingRole)
	}
	if _, ok := standing[grantRole]; ok {
		t.Fatalf("SECURITY: authz_held_standing wrongly includes JIT-granted role %s", grantRole)
	}
}

// heldRoleSet runs a single-uuid-arg role_id query and collects the result set.
func heldRoleSet(t *testing.T, pool *pgxpool.Pool, query string, user uuid.UUID) map[uuid.UUID]struct{} {
	t.Helper()
	set := map[uuid.UUID]struct{}{}
	rows, err := pool.Query(context.Background(), query, user)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer rows.Close()
	for rows.Next() {
		var r uuid.UUID
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan: %v", err)
		}
		set[r] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return set
}

func TestAuthzGlobalHeldParity(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	_, _, _, _, _, _, _, _ = seedTree(t, pool)
	u := mustSeedUser(t, pool, "global@x")
	old := map[uuid.UUID]struct{}{}
	rows, err := pool.Query(ctx, globalHeldCTE+`
SELECT DISTINCT role_id FROM global_held`, pgxNamed(u))
	if err != nil {
		t.Fatalf("old: %v", err)
	}
	for rows.Next() {
		var r uuid.UUID
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("old scan: %v", err)
		}
		old[r] = struct{}{}
	}
	rows.Close()
	neu := map[uuid.UUID]struct{}{}
	rows2, err := pool.Query(ctx, `SELECT role_id FROM authz_global_held($1)`, u)
	if err != nil {
		t.Fatalf("fn: %v", err)
	}
	for rows2.Next() {
		var r uuid.UUID
		if err := rows2.Scan(&r); err != nil {
			t.Fatalf("new scan: %v", err)
		}
		neu[r] = struct{}{}
	}
	rows2.Close()
	if len(old) != len(neu) {
		t.Fatalf("old=%d new=%d", len(old), len(neu))
	}
}

func TestAuthzRoleGoalsBacksHoldsRole(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	_, alice, _, _, _, _, a1, _ := seedTree(t, pool)
	// find a role alice holds on a1 via the OLD resolver, then confirm the function
	// yields the same EXISTS answer for that (role, asset).
	// (seedTree binds alice to some role on a1; discover it.)
	var roleID uuid.UUID
	if err := pool.QueryRow(ctx, heldCTE+`
SELECT role_id FROM held WHERE object_kind='asset' AND object_id=@assetID LIMIT 1`,
		pgx.NamedArgs{"user": alice, "assetID": a1}).Scan(&roleID); err != nil {
		t.Skipf("seedTree gave alice no asset role: %v", err)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM authz_role_goals($1,'asset',$2) g
    JOIN role_bindings rb ON rb.role_id = g.role_id
      AND rb.scope_asset_id = g.object_id
      AND (rb.subject_user_id = $3 OR rb.subject_group_id IN (SELECT group_id FROM authz_user_groups($3)))
    WHERE authz_user_is_active($3)
)`, roleID, a1, alice).Scan(&ok); err != nil {
		t.Fatalf("goals: %v", err)
	}
	if !ok {
		t.Fatalf("authz_role_goals failed to back HoldsRole for role %s on %s", roleID, a1)
	}
}

func TestAuthzEffectivePolicyParity(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	// Minimal fixture: role r, folder f with asset a, one folder-scoped request_policy.
	// NB: `assets` has no target_address column (that lives on ssh_asset_config), and
	// names must satisfy the `^[a-z0-9_-]+$` check constraint.
	var role, folder, asset, policy uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO roles(name) VALUES('r') RETURNING id`).Scan(&role); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO folders(name) VALUES('f') RETURNING id`).Scan(&folder); err != nil {
		t.Fatalf("seed folder: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO assets(name, folder_id) VALUES('a',$1) RETURNING id`, folder).Scan(&asset); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO request_policies(role_id, scope_folder_id, required_approvals)
		VALUES($1,$2,1) RETURNING id`, role, folder).Scan(&policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	var gotPolicy uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT policy_id FROM authz_effective_request_policy($1,$2)`, role, asset).Scan(&gotPolicy); err != nil {
		t.Fatalf("fn: %v", err)
	}
	if gotPolicy != policy {
		t.Fatalf("want winning policy %s, got %s", policy, gotPolicy)
	}
}

func TestAuthzRoleGoalPathsShape(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	_, alice, _, _, _, _, a1, _ := seedTree(t, pool)
	var role uuid.UUID
	if err := pool.QueryRow(ctx, heldCTE+`
SELECT role_id FROM held WHERE object_kind='asset' AND object_id=@assetID LIMIT 1`,
		pgx.NamedArgs{"user": alice, "assetID": a1}).Scan(&role); err != nil {
		t.Skipf("no role: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM authz_role_goal_paths($1,$2,$3)`, alice, role, a1).Scan(&n); err != nil {
		t.Fatalf("fn: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected >=1 derivation path")
	}
}
