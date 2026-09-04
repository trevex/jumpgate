package migrate

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
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

func TestMigration0006TargetIdentity(t *testing.T) {
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

	for _, table := range []string{
		"target_probe_jobs",
		"target_probe_attempts",
		"target_identity_observations",
		"target_identity_evidence",
		"target_trust_anchors",
	} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	var assetID string
	if err := pool.QueryRow(ctx, `
		WITH folder AS (
			INSERT INTO folders (name) VALUES ('target-identity-test') RETURNING id
		)
		INSERT INTO assets (folder_id, name, kind)
		SELECT id, 'target', 'ssh' FROM folder
		RETURNING id`).Scan(&assetID); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	var revision int64
	err = pool.QueryRow(ctx, `SELECT endpoint_revision FROM assets WHERE id=$1`, assetID).Scan(&revision)
	if err != nil || revision != 1 {
		t.Fatalf("endpoint revision = %d, %v; want 1", revision, err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE assets SET endpoint_revision = 0 WHERE id = $1`, assetID); err == nil {
		t.Fatal("non-positive asset endpoint revision accepted")
	}

	var jobID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO target_probe_jobs
			(asset_id, endpoint_revision, protocol, state, reason)
		VALUES ($1, 1, 'ssh', 'queued', 'onboarding')
		RETURNING id`, assetID).Scan(&jobID); err != nil {
		t.Fatalf("insert probe job: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_probe_jobs
			(asset_id, endpoint_revision, protocol, state, reason)
		VALUES ($1, 1, 'ssh', 'queued', 'onboarding')`, assetID); err == nil {
		t.Fatal("duplicate active onboarding job accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_probe_jobs
			(asset_id, endpoint_revision, protocol, state, reason)
		VALUES ($1, 1, 'smtp', 'queued', 'manual')`, assetID); err == nil {
		t.Fatal("invalid probe protocol accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_probe_jobs
			(asset_id, endpoint_revision, protocol, state, reason)
		VALUES ($1, 1, 'ssh', 'running', 'manual')`, assetID); err == nil {
		t.Fatal("invalid probe state accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_probe_jobs
			(asset_id, endpoint_revision, protocol, state, reason)
		VALUES ($1, 0, 'ssh', 'queued', 'manual')`, assetID); err == nil {
		t.Fatal("non-positive job endpoint revision accepted")
	}

	var attemptID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO target_probe_attempts
			(job_id, attempt_number, worker_id, lease_token_hash, lease_expires_at,
			 completed_at, outcome)
		VALUES ($1, 1, 'worker-1', decode(repeat('ab', 32), 'hex'), now() + interval '1 minute',
		        now(), 'succeeded')
		RETURNING id`, jobID).Scan(&attemptID); err != nil {
		t.Fatalf("insert completed attempt: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE target_probe_attempts SET outcome = 'failed' WHERE id = $1`, attemptID); err == nil {
		t.Fatal("completed attempt update accepted")
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM target_probe_attempts WHERE id = $1`, attemptID); err == nil {
		t.Fatal("completed attempt delete accepted")
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM target_probe_jobs WHERE id = $1`, jobID); err == nil {
		t.Fatal("job delete cascaded through completed attempt history")
	}

	var observationID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO target_identity_observations
			(job_id, asset_id, endpoint_revision, worker_id, source,
			 resolved_addresses, protocol_metadata, outcome)
		VALUES ($1, $2, 1, 'worker-1', 'probe', '["192.0.2.10"]', '{}', 'succeeded')
		RETURNING id`, jobID, assetID).Scan(&observationID); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE target_identity_observations SET outcome = 'failed' WHERE id = $1`, observationID); err == nil {
		t.Fatal("observation update accepted")
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM target_identity_observations WHERE id = $1`, observationID); err == nil {
		t.Fatal("observation delete accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_identity_evidence
			(observation_id, kind, algorithm, sha256_fingerprint, public_material)
		VALUES ($1, 'password', 'ed25519', 'SHA256:test', 'public')`, observationID); err == nil {
		t.Fatal("invalid evidence kind accepted")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO target_trust_anchors
			(asset_id, endpoint_revision, kind, sha256_fingerprint, public_material, source)
		VALUES ($1, 1, 'password', 'SHA256:test', 'public', 'manual')`, assetID); err == nil {
		t.Fatal("invalid trust-anchor kind accepted")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM assets WHERE id = $1`, assetID); err != nil {
		t.Fatalf("asset cascade delete: %v", err)
	}
	for _, table := range []string{
		"target_probe_jobs",
		"target_probe_attempts",
		"target_identity_observations",
		"target_identity_evidence",
		"target_trust_anchors",
	} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count %s after asset delete: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s rows after asset delete = %d; want 0", table, count)
		}
	}
}

func TestTargetIdentityQueriesLeaseOnlyCurrentRevision(t *testing.T) {
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
	queries := sqlc.New(pool)

	var assetID uuid.UUID
	if err := pool.QueryRow(ctx, `
		WITH folder AS (
			INSERT INTO folders (name) VALUES ('target-query-test') RETURNING id
		)
		INSERT INTO assets (folder_id, name, kind)
		SELECT id, 'target', 'ssh' FROM folder
		RETURNING id`).Scan(&assetID); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO ssh_asset_config (asset_id, target_address, host_public_key)
		VALUES ($1, 'target.example:22', '')`, assetID); err != nil {
		t.Fatalf("insert SSH config: %v", err)
	}

	now := time.Now().UTC()
	staleJob, err := queries.CreateProbeJob(ctx, sqlc.CreateProbeJobParams{
		AssetID:          assetID,
		EndpointRevision: 1,
		Protocol:         "ssh",
		Reason:           "onboarding",
		MaxAttempts:      3,
		NextAttemptAt:    pgtype.Timestamptz{Time: now.Add(-time.Minute), Valid: true},
	})
	if err != nil {
		t.Fatalf("create stale job: %v", err)
	}
	revision, err := queries.IncrementAssetEndpointRevision(ctx, assetID)
	if err != nil {
		t.Fatalf("increment endpoint revision: %v", err)
	}
	if revision != 2 {
		t.Fatalf("incremented endpoint revision = %d; want 2", revision)
	}
	currentJob, err := queries.CreateProbeJob(ctx, sqlc.CreateProbeJobParams{
		AssetID:          assetID,
		EndpointRevision: revision,
		Protocol:         "ssh",
		Reason:           "endpoint_changed",
		MaxAttempts:      3,
		NextAttemptAt:    pgtype.Timestamptz{Time: now, Valid: true},
	})
	if err != nil {
		t.Fatalf("create current job: %v", err)
	}

	leaseHash := bytes.Repeat([]byte{0x42}, 32)
	claimed, err := queries.ClaimProbeJob(ctx, sqlc.ClaimProbeJobParams{
		WorkerID:       pgtype.Text{String: "worker-1", Valid: true},
		LeaseTokenHash: leaseHash,
		LeaseExpiresAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true},
	})
	if err != nil {
		t.Fatalf("claim current job: %v", err)
	}
	if claimed.JobID != currentJob.ID {
		t.Fatalf("claimed job = %s; want current-revision job %s (stale job %s)", claimed.JobID, currentJob.ID, staleJob.ID)
	}
	if claimed.EndpointRevision != 2 || claimed.TargetAddress != "target.example:22" {
		t.Fatalf("claimed revision/address = %d/%q; want 2/target.example:22", claimed.EndpointRevision, claimed.TargetAddress)
	}

	_, err = queries.CompleteProbeAttempt(ctx, sqlc.CompleteProbeAttemptParams{
		Outcome:        "succeeded",
		JobID:          currentJob.ID,
		WorkerID:       pgtype.Text{String: "worker-1", Valid: true},
		LeaseTokenHash: bytes.Repeat([]byte{0x24}, 32),
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("complete with wrong lease hash = %v; want pgx.ErrNoRows", err)
	}

	completed, err := queries.CompleteProbeAttempt(ctx, sqlc.CompleteProbeAttemptParams{
		Outcome:        "succeeded",
		JobID:          currentJob.ID,
		WorkerID:       pgtype.Text{String: "worker-1", Valid: true},
		LeaseTokenHash: leaseHash,
	})
	if err != nil {
		t.Fatalf("complete current attempt: %v", err)
	}
	if !completed.Outcome.Valid || completed.Outcome.String != "succeeded" || !completed.CompletedAt.Valid {
		t.Fatalf("completed attempt outcome/time = %#v/%#v", completed.Outcome, completed.CompletedAt)
	}

	if _, err := queries.ClaimProbeJob(ctx, sqlc.ClaimProbeJobParams{
		WorkerID:       pgtype.Text{String: "worker-2", Valid: true},
		LeaseTokenHash: bytes.Repeat([]byte{0x11}, 32),
		LeaseExpiresAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true},
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("claim with only stale queued job remaining = %v; want pgx.ErrNoRows", err)
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
