package approvals_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func caps() []byte { b, _ := json.Marshal([]string{}); return b }

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestApprovalResolver(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)

	// Roles
	dba, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "dba", ResourceType: "asset", Capabilities: caps()})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "owner", ResourceType: "asset", Capabilities: caps()})
	if err != nil {
		t.Fatal(err)
	}
	readonly, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "readonly", ResourceType: "asset", Capabilities: caps()})
	if err != nil {
		t.Fatal(err)
	}

	// Folders: prod (root), prod/db (parent=prod)
	prod, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	proddb, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "db", ParentID: pg(prod.ID)})
	if err != nil {
		t.Fatal(err)
	}

	// Asset pg in prod/db
	pgAsset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: proddb.ID, Name: "pg", Labels: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	// Users
	alice, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	carol, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "carol@x", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}

	// Group leads with carol as member
	leads, err := q.CreateGroup(ctx, "leads")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, gen.AddUserToGroupParams{GroupID: leads.ID, MemberUserID: pg(carol.ID)}); err != nil {
		t.Fatal(err)
	}

	// Role-level DEFAULT rule for dba: required_approvals=1, approver_role_id=owner
	defaultRule, err := q.CreateApprovalRule(ctx, gen.CreateApprovalRuleParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
		ApproverRoleID:    pg(owner.ID),
		// ScopeFolderID and ScopeAssetID left zero (NULL) => role default
	})
	if err != nil {
		t.Fatal(err)
	}

	// Explicit approver on the default rule: group leads
	if _, err := q.AddRuleApprover(ctx, gen.AddRuleApproverParams{
		RuleID:         defaultRule.ID,
		SubjectGroupID: pg(leads.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Standing role binding: alice -> owner on folder prod (inherited to pg)
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID:        owner.ID,
		Kind:          "standing",
		ScopeFolderID: pg(prod.ID),
		SubjectUserID: pg(alice.ID),
	}); err != nil {
		t.Fatal(err)
	}

	r := approvals.New(pool)

	// --- Assertion 1: EffectiveRule(dba, pg) returns role default, RequiredApprovals=1 ---
	t.Run("role-default rule", func(t *testing.T) {
		rule, err := r.EffectiveRule(ctx, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule error: %v", err)
		}
		if rule == nil {
			t.Fatal("EffectiveRule returned nil; want role default rule")
		}
		if rule.RequiredApprovals != 1 {
			t.Fatalf("RequiredApprovals = %d; want 1", rule.RequiredApprovals)
		}
	})

	// --- Assertion 2: IsApprover(alice, dba, pg) == true (owner standing on prod, inherited) ---
	t.Run("owner-approver via standing+inheritance", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, alice.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(alice) error: %v", err)
		}
		if !ok {
			t.Fatal("IsApprover(alice) = false; want true (owner standing on prod → pg)")
		}
	})

	// --- Assertion 3: IsApprover(carol, dba, pg) == true (member of leads, explicit approver) ---
	t.Run("explicit-group-approver", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, carol.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(carol) error: %v", err)
		}
		if !ok {
			t.Fatal("IsApprover(carol) = false; want true (member of leads, explicit approver on default rule)")
		}
	})

	// --- Assertion 4: IsApprover(bob, dba, pg) == false ---
	t.Run("non-approver", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, bob.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(bob) error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover(bob) = true; want false")
		}
	})

	// --- Assertion 5: Asset-override rule beats role default ---
	// Add asset-override for dba on pg: required_approvals=3, no approver_role
	assetOverride, err := q.CreateApprovalRule(ctx, gen.CreateApprovalRuleParams{
		RoleID:            dba.ID,
		ScopeAssetID:      pg(pgAsset.ID),
		RequiredApprovals: 3,
		// no ApproverRoleID
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = assetOverride

	t.Run("asset-override-precedence-required-approvals", func(t *testing.T) {
		rule, err := r.EffectiveRule(ctx, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule error: %v", err)
		}
		if rule == nil {
			t.Fatal("EffectiveRule returned nil; want asset override")
		}
		if rule.RequiredApprovals != 3 {
			t.Fatalf("RequiredApprovals = %d; want 3 (asset override)", rule.RequiredApprovals)
		}
	})

	t.Run("asset-override-alice-not-approver", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, alice.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(alice) error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover(alice) = true; want false (override has no approver_role)")
		}
	})

	t.Run("asset-override-carol-not-approver", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, carol.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(carol) error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover(carol) = true; want false (explicit approvers were on default rule, not override)")
		}
	})

	// --- Assertion 6: No rule for readonly → not requestable ---
	t.Run("no-rule-not-requestable", func(t *testing.T) {
		rule, err := r.EffectiveRule(ctx, readonly.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule(readonly) error: %v", err)
		}
		if rule != nil {
			t.Fatalf("EffectiveRule(readonly) = %+v; want nil", rule)
		}
	})

	t.Run("no-rule-alice-not-approver-for-readonly", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, alice.ID, readonly.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(alice, readonly) error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover(alice, readonly) = true; want false (no rule)")
		}
	})

	// --- Assertion 7: Folder-override precedence ---
	// Delete asset override; add folder override on prod/db required=2
	if err := q.DeleteApprovalRule(ctx, assetOverride.ID); err != nil {
		t.Fatal(err)
	}
	folderOverride, err := q.CreateApprovalRule(ctx, gen.CreateApprovalRuleParams{
		RoleID:            dba.ID,
		ScopeFolderID:     pg(proddb.ID),
		RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = folderOverride

	t.Run("folder-override-precedence", func(t *testing.T) {
		rule, err := r.EffectiveRule(ctx, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule error: %v", err)
		}
		if rule == nil {
			t.Fatal("EffectiveRule returned nil; want folder override")
		}
		if rule.RequiredApprovals != 2 {
			t.Fatalf("RequiredApprovals = %d; want 2 (nearest ancestor folder prod/db)", rule.RequiredApprovals)
		}
	})
}
