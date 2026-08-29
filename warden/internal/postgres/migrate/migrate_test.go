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
	// Inserting a folder auto-registers its name via trg_folders_register_name, so a
	// duplicate sibling name collides on the catalog_names unique index and aborts the
	// folder INSERT itself. Drive that real mechanism rather than registering by hand.
	var fid string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('prod') RETURNING id`).Scan(&fid); err != nil {
		t.Fatalf("insert folder: %v", err)
	}
	// The AFTER INSERT trigger must have auto-registered the name.
	var registered int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM catalog_names WHERE parent_id IS NULL AND name = 'prod' AND folder_id = $1`, fid).Scan(&registered); err != nil {
		t.Fatalf("check registration: %v", err)
	}
	if registered != 1 {
		t.Fatalf("folder insert did not auto-register a catalog_names row (got %d, want 1)", registered)
	}
	// A second top-level 'prod' collides on uq_sibling_root via the trigger.
	if _, err := pool.Exec(ctx, `INSERT INTO folders (name) VALUES ('prod')`); err == nil {
		t.Fatal("duplicate top-level folder name accepted, want unique violation")
	}

	// Non-root sibling uniqueness (uq_sibling_child, WHERE parent_id IS NOT NULL): two
	// child folders with the same name under the same parent collide.
	var parentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('parent') RETURNING id`).Scan(&parentID); err != nil {
		t.Fatalf("insert parent folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO folders (name, parent_id) VALUES ('child', $1)`, parentID); err != nil {
		t.Fatalf("insert first child folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO folders (name, parent_id) VALUES ('child', $1)`, parentID); err == nil {
		t.Fatal("duplicate child name under same parent accepted, want unique violation")
	}

	// The same name under a DIFFERENT parent is allowed — sibling scope only.
	var otherParent string
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (name) VALUES ('other') RETURNING id`).Scan(&otherParent); err != nil {
		t.Fatalf("insert other parent folder: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO folders (name, parent_id) VALUES ('child', $1)`, otherParent); err != nil {
		t.Fatalf("same child name under a different parent must be allowed: %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO folders (name) VALUES ('Prod')`); err == nil {
		t.Fatal("uppercase folder name accepted, want check violation")
	}
}
