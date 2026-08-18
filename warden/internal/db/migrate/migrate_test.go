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
