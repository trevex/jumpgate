package migrate

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func TestUpCreatesAuthObjects(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'auth_tokens')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("auth_tokens table not created")
	}
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_admin')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("users.is_admin column not created")
	}
}

func TestUpCreatesSchema(t *testing.T) {
	dsn := testsupport.StartPostgres(t)

	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	for _, table := range []string{
		"users", "groups", "group_memberships", "folders", "assets", "roles", "role_bindings",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}
}

func TestUpCreatesRequestPolicies(t *testing.T) {
	dsn := testsupport.StartPostgres(t)

	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	for _, table := range []string{
		"request_policies", "request_policy_subjects",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	// The old table names must NOT survive the rename.
	for _, table := range []string{
		"approval_rules", "approval_rule_approvers",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if exists {
			t.Fatalf("legacy table %q still exists after rename", table)
		}
	}

	// users.deactivated_at must exist.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='deactivated_at')`).Scan(&exists); err != nil {
		t.Fatalf("check users.deactivated_at: %v", err)
	}
	if !exists {
		t.Fatal("users.deactivated_at column was not created")
	}
}

func TestUpCreatesRoleGrants(t *testing.T) {
	dsn := testsupport.StartPostgres(t)

	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var exists bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
		"role_grants").Scan(&exists)
	if err != nil {
		t.Fatalf("check role_grants: %v", err)
	}
	if !exists {
		t.Fatal("table \"role_grants\" was not created")
	}
}

func TestUpCreatesVault(t *testing.T) {
	dsn := testsupport.StartPostgres(t)

	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	for _, table := range []string{
		"ca_keys", "asset_secrets", "ssh_asset_config",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	// assets.kind column must exist.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='assets' AND column_name='kind')`).Scan(&exists); err != nil {
		t.Fatalf("check assets.kind: %v", err)
	}
	if !exists {
		t.Fatal("assets.kind column was not created")
	}
}

func TestUpCreatesAccessRequests(t *testing.T) {
	dsn := testsupport.StartPostgres(t)

	if err := Up(dsn); err != nil {
		t.Fatalf("Up: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	for _, table := range []string{
		"access_requests", "access_request_approvals", "access_grants",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	// request_policies.max_duration column must exist.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='request_policies' AND column_name='max_duration')`).Scan(&exists); err != nil {
		t.Fatalf("check request_policies.max_duration: %v", err)
	}
	if !exists {
		t.Fatal("request_policies.max_duration column was not created")
	}
}

func TestCatalogNamesEnforcesSiblingUniqueness(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Root sibling uniqueness (uq_sibling_root, WHERE parent_id IS NULL):
	// register a top-level folder name, then register a SECOND, distinct
	// folder (different folder_id) with the same name and parent_id NULL. The
	// distinct folder_id proves the collision is on `name`, not on folder_id.
	var fid string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('prod') RETURNING id`).Scan(&fid); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO catalog_names (parent_id, name, folder_id) VALUES (NULL, 'prod', $1)`, fid); err != nil {
		t.Fatalf("register folder name: %v", err)
	}
	var fid2 string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('prod') RETURNING id`).Scan(&fid2); err != nil {
		t.Fatalf("insert second folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO catalog_names (parent_id, name, folder_id) VALUES (NULL, 'prod', $1)`, fid2); err == nil {
		t.Fatal("duplicate top-level name accepted, want unique violation")
	}

	// Non-root sibling uniqueness (uq_sibling_child, WHERE parent_id IS NOT NULL):
	// create a parent folder, then register two CHILD folders with the same
	// name under it (parent_id = the parent's id, distinct folder_id each).
	var parentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('parent') RETURNING id`).Scan(&parentID); err != nil {
		t.Fatalf("insert parent folder: %v", err)
	}
	var child1 string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name, parent_id) VALUES ('child', $1) RETURNING id`, parentID).Scan(&child1); err != nil {
		t.Fatalf("insert first child folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO catalog_names (parent_id, name, folder_id) VALUES ($1, 'child', $2)`, parentID, child1); err != nil {
		t.Fatalf("register child folder name: %v", err)
	}
	var child2 string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name, parent_id) VALUES ('child', $1) RETURNING id`, parentID).Scan(&child2); err != nil {
		t.Fatalf("insert second child folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO catalog_names (parent_id, name, folder_id) VALUES ($1, 'child', $2)`, parentID, child2); err == nil {
		t.Fatal("duplicate child name under same parent accepted, want unique violation")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO folders (name) VALUES ('Prod')`); err == nil {
		t.Fatal("uppercase folder name accepted, want check violation")
	}
}
