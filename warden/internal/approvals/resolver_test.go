package approvals_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

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
	q := sqlc.New(pool)

	// Roles
	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	readonly, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "readonly"})
	if err != nil {
		t.Fatal(err)
	}

	// owner cascades down folders via an explicit parent self-rule (IsApprover now
	// resolves the approver-role through the explicit role-rewrite graph).
	if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: owner.ID, SourceRoleID: owner.ID, Via: "parent"}); err != nil {
		t.Fatal(err)
	}

	// Folders: prod (root), prod/db (parent=prod)
	prod, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	proddb, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "db", ParentID: pg(prod.ID)})
	if err != nil {
		t.Fatal(err)
	}

	// Asset pg in prod/db
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: proddb.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	// Users
	alice, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	carol, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "carol@x", DisplayName: "Carol"})
	if err != nil {
		t.Fatal(err)
	}

	// Group leads with carol as member
	leads, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "leads"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: leads.ID, MemberUserID: pg(carol.ID)}); err != nil {
		t.Fatal(err)
	}

	// Role-level DEFAULT rule for dba: required_approvals=1, approver_role_id=owner
	defaultRule, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
		ApproverRoleID:    pg(owner.ID),
		// ScopeFolderID and ScopeAssetID left zero (NULL) => role default
	})
	if err != nil {
		t.Fatal(err)
	}

	// Explicit approver on the default rule: group leads
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:       defaultRule.ID,
		Kind:           "approver",
		SubjectGroupID: pg(leads.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Standing role binding: alice -> owner on folder prod (inherited to pg)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        owner.ID,
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

	// --- Assertion 2b: approver-role requires an explicit `parent` role_grant to cascade ---
	// The approver-role branch of IsApprover resolves via HoldsRole (explicit
	// role_grants), NOT the implicit folder cascade. A folder-scoped standing
	// binding of an approver-role with NO `parent` rule must NOT confer approver
	// status on descendant assets; adding the `parent` self-rule flips it.
	// Uses fresh roles/users (custodian/keeper/dave) so existing assertions are
	// untouched.
	t.Run("approver-role-requires-explicit-parent-rule", func(t *testing.T) {
		custodian, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "custodian"})
		if err != nil {
			t.Fatal(err)
		}
		keeper, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "keeper"})
		if err != nil {
			t.Fatal(err)
		}
		// Role-default rule for custodian whose approver-role is keeper.
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID:            custodian.ID,
			RequiredApprovals: 1,
			ApproverRoleID:    pg(keeper.ID),
		}); err != nil {
			t.Fatal(err)
		}
		dave, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "dave@x", DisplayName: "Dave"})
		if err != nil {
			t.Fatal(err)
		}
		// keeper STANDING on folder prod; pgAsset lives in prod/db (a descendant).
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        keeper.ID,
			ScopeFolderID: pg(prod.ID),
			SubjectUserID: pg(dave.ID),
		}); err != nil {
			t.Fatal(err)
		}

		// Without a `parent` rule, keeper does not cascade prod → prod/db → pg.
		ok, err := r.IsApprover(ctx, dave.ID, custodian.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(dave) error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover(dave) = true; want false (keeper has no `parent` role_grant, no implicit cascade)")
		}

		// Add the explicit parent self-rule; keeper now cascades to descendants.
		if _, err := q.CreateRoleGrant(ctx, sqlc.CreateRoleGrantParams{RoleID: keeper.ID, SourceRoleID: keeper.ID, Via: "parent"}); err != nil {
			t.Fatal(err)
		}
		ok, err = r.IsApprover(ctx, dave.ID, custodian.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover(dave) after parent rule error: %v", err)
		}
		if !ok {
			t.Fatal("IsApprover(dave) = false; want true (keeper ⊇ keeper via parent cascades prod → pg)")
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
	assetOverride, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
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
	if err := q.DeleteRequestPolicy(ctx, assetOverride.ID); err != nil {
		t.Fatal(err)
	}
	folderOverride, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
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

	// --- Assertion 8: EffectiveRule surfaces max_duration when set on the policy ---
	// Fresh role/asset so existing assertions are untouched. A role-default policy
	// with a 1h cap must round-trip through EffectiveRule.MaxDuration; a policy with
	// NULL max_duration must yield an invalid interval.
	t.Run("max-duration-round-trips", func(t *testing.T) {
		capped, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "capped"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
			RoleID:            capped.ID,
			RequiredApprovals: 0,
			MaxDuration:       pgtype.Interval{Microseconds: 3600 * 1_000_000, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
		rule, err := r.EffectiveRule(ctx, capped.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule(capped) error: %v", err)
		}
		if rule == nil {
			t.Fatal("EffectiveRule(capped) returned nil; want policy with max_duration")
		}
		if !rule.MaxDuration.Valid || rule.MaxDuration.Microseconds != 3600*1_000_000 {
			t.Fatalf("MaxDuration = %+v; want valid 3600s", rule.MaxDuration)
		}

		// dba's folder-override policy has NULL max_duration → invalid interval.
		dbaRule, err := r.EffectiveRule(ctx, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("EffectiveRule(dba) error: %v", err)
		}
		if dbaRule.MaxDuration.Valid {
			t.Fatalf("MaxDuration = %+v; want invalid (NULL)", dbaRule.MaxDuration)
		}
	})
}

// TestIsEligibleRequester covers the new (not-yet-wired) requester-eligibility
// path: eligibility = holds the policy's requester_role on the asset (via the
// explicit role-rewrite graph) OR is an explicit kind='requester' subject.
func TestIsEligibleRequester(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	r := approvals.New(pool)

	// Roles: dba (the requestable role) and requester (the standing role that
	// confers requester eligibility).
	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	requester, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "requester"})
	if err != nil {
		t.Fatal(err)
	}

	// Folder + asset.
	prod, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: prod.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	// Users: alice holds `requester` standing, bob holds nothing, dave is an
	// explicit requester subject.
	alice, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "alice@x", DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "bob@x", DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	dave, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "dave@x", DisplayName: "Dave"})
	if err != nil {
		t.Fatal(err)
	}

	// Role-default policy for dba with requester_role_id = requester.
	policy, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
		RequesterRoleID:   pg(requester.ID),
	})
	if err != nil {
		t.Fatal(err)
	}

	// alice: standing `requester` on the asset → eligible via requester_role.
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        requester.ID,
		ScopeAssetID:  pg(pgAsset.ID),
		SubjectUserID: pg(alice.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// dave: explicit kind='requester' subject on the policy.
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:      policy.ID,
		Kind:          "requester",
		SubjectUserID: pg(dave.ID),
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("requester-role-standing", func(t *testing.T) {
		ok, err := r.IsEligibleRequester(ctx, alice.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester(alice) error: %v", err)
		}
		if !ok {
			t.Fatal("IsEligibleRequester(alice) = false; want true (holds requester standing on asset)")
		}
	})

	t.Run("no-eligibility", func(t *testing.T) {
		ok, err := r.IsEligibleRequester(ctx, bob.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester(bob) error: %v", err)
		}
		if ok {
			t.Fatal("IsEligibleRequester(bob) = true; want false (no requester role, not a requester subject)")
		}
	})

	t.Run("explicit-requester-subject", func(t *testing.T) {
		ok, err := r.IsEligibleRequester(ctx, dave.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester(dave) error: %v", err)
		}
		if !ok {
			t.Fatal("IsEligibleRequester(dave) = false; want true (explicit kind='requester' subject)")
		}
	})

	t.Run("approver-subject-is-not-a-requester", func(t *testing.T) {
		// An approver-kind subject must NOT be treated as an eligible requester.
		erin, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "erin@x", DisplayName: "Erin"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
			PolicyID:      policy.ID,
			Kind:          "approver",
			SubjectUserID: pg(erin.ID),
		}); err != nil {
			t.Fatal(err)
		}
		ok, err := r.IsEligibleRequester(ctx, erin.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester(erin) error: %v", err)
		}
		if ok {
			t.Fatal("IsEligibleRequester(erin) = true; want false (approver subject, not requester)")
		}
	})
}

// deactivateUser marks a user deactivated directly in the store.
func deactivateUser(t *testing.T, pool *pgxpool.Pool, user uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET deactivated_at = now() WHERE id = $1`, user); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
}

// TestDeactivatedExplicitApproverSubject proves a user named as an explicit
// kind='approver' subject on a policy is an approver while active, but NOT once
// deactivated — a deactivated user counts for nothing in governance.
func TestDeactivatedExplicitApproverSubject(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	r := approvals.New(pool)

	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "deact-approver@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}

	// Role-default policy with NO approver_role: the only approver path is the
	// explicit subject below.
	policy, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:      policy.ID,
		Kind:          "approver",
		SubjectUserID: pg(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Active: explicit approver subject → approver.
	ok, err := r.IsApprover(ctx, user.ID, dba.ID, pgAsset.ID)
	if err != nil {
		t.Fatalf("active: IsApprover error: %v", err)
	}
	if !ok {
		t.Fatal("active: IsApprover = false; want true (explicit approver subject)")
	}

	// Deactivated: explicit approver subject no longer counts.
	deactivateUser(t, pool, user.ID)
	ok, err = r.IsApprover(ctx, user.ID, dba.ID, pgAsset.ID)
	if err != nil {
		t.Fatalf("deactivated: IsApprover error: %v", err)
	}
	if ok {
		t.Fatal("deactivated: IsApprover = true; want false (deactivated approver subject counts for nothing)")
	}
}

// TestDeactivatedExplicitRequesterSubject proves a user named as an explicit
// kind='requester' subject on a policy is an eligible requester while active, but
// NOT once deactivated.
func TestDeactivatedExplicitRequesterSubject(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	r := approvals.New(pool)

	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "deact-req@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}

	// Role-default policy with NO requester_role: the only requester path is the
	// explicit subject below.
	policy, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.AddPolicySubject(ctx, sqlc.AddPolicySubjectParams{
		PolicyID:      policy.ID,
		Kind:          "requester",
		SubjectUserID: pg(user.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// Active: explicit requester subject → eligible.
	ok, err := r.IsEligibleRequester(ctx, user.ID, dba.ID, pgAsset.ID)
	if err != nil {
		t.Fatalf("active: IsEligibleRequester error: %v", err)
	}
	if !ok {
		t.Fatal("active: IsEligibleRequester = false; want true (explicit requester subject)")
	}

	// Deactivated: explicit requester subject no longer counts.
	deactivateUser(t, pool, user.ID)
	ok, err = r.IsEligibleRequester(ctx, user.ID, dba.ID, pgAsset.ID)
	if err != nil {
		t.Fatalf("deactivated: IsEligibleRequester error: %v", err)
	}
	if ok {
		t.Fatal("deactivated: IsEligibleRequester = true; want false (deactivated requester subject counts for nothing)")
	}
}

// fabricateGrant inserts a minimal access_requests + active access_grants row for
// (user, role, asset), returning the grant id. Mirrors the authz test helper;
// used to prove a JIT-granted role confers access but NOT governance eligibility.
func fabricateGrant(t *testing.T, pool *pgxpool.Pool, user, role, asset uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var reqID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_requests (requester_user_id, role_id, asset_id, requested_duration, required_approvals, granted_duration, status, resolved_at)
VALUES ($1, $2, $3, '1 hour', 1, '1 hour', 'granted', now())
RETURNING id`, user, role, asset).Scan(&reqID); err != nil {
		t.Fatalf("fabricate access_request: %v", err)
	}
	var grantID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO access_grants (request_id, role_id, scope_asset_id, subject_user_id, expires_at)
VALUES ($1, $2, $3, $4, now() + '1 hour'::interval)
RETURNING id`, reqID, role, asset, user).Scan(&grantID); err != nil {
		t.Fatalf("fabricate access_grant: %v", err)
	}
	return grantID
}

// TestGrantedApproverRoleIsNotApprover (M3c T1): a user who holds the policy's
// approver_role ONLY via an active JIT grant is NOT an approver; a STANDING binding
// of that approver_role makes them an approver. Governance uses HoldsRoleStanding.
func TestGrantedApproverRoleIsNotApprover(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	r := approvals.New(pool)

	// Roles: dba (the requestable role) + approver (confers approver eligibility).
	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	approver, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "approver"})
	if err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "grantapprover@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}

	// Role-default policy for dba, approver_role = approver.
	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
		ApproverRoleID:    pg(approver.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// user holds `approver` ONLY via an active JIT grant on the asset.
	fabricateGrant(t, pool, user.ID, approver.ID, pgAsset.ID)

	t.Run("granted-approver-role-is-not-approver", func(t *testing.T) {
		ok, err := r.IsApprover(ctx, user.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover error: %v", err)
		}
		if ok {
			t.Fatal("IsApprover = true; want false (approver_role held only via JIT grant confers no governance)")
		}
	})

	t.Run("standing-approver-role-is-approver", func(t *testing.T) {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        approver.ID,
			ScopeAssetID:  pg(pgAsset.ID),
			SubjectUserID: pg(user.ID),
		}); err != nil {
			t.Fatal(err)
		}
		ok, err := r.IsApprover(ctx, user.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsApprover error: %v", err)
		}
		if !ok {
			t.Fatal("IsApprover = false; want true (standing binding of approver_role)")
		}
	})
}

// TestGrantedRequesterRoleIsNotEligible (M3c T2): a user who holds the policy's
// requester_role ONLY via an active JIT grant is NOT an eligible requester; a
// STANDING binding of that requester_role makes them eligible.
func TestGrantedRequesterRoleIsNotEligible(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)
	r := approvals.New(pool)

	dba, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "dba"})
	if err != nil {
		t.Fatal(err)
	}
	requester, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "requester"})
	if err != nil {
		t.Fatal(err)
	}

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	pgAsset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "grantrequester@x", DisplayName: "U"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := q.CreateRequestPolicy(ctx, sqlc.CreateRequestPolicyParams{
		RoleID:            dba.ID,
		RequiredApprovals: 1,
		RequesterRoleID:   pg(requester.ID),
	}); err != nil {
		t.Fatal(err)
	}

	// user holds `requester` ONLY via an active JIT grant on the asset.
	fabricateGrant(t, pool, user.ID, requester.ID, pgAsset.ID)

	t.Run("granted-requester-role-is-not-eligible", func(t *testing.T) {
		ok, err := r.IsEligibleRequester(ctx, user.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester error: %v", err)
		}
		if ok {
			t.Fatal("IsEligibleRequester = true; want false (requester_role held only via JIT grant confers no governance)")
		}
	})

	t.Run("standing-requester-role-is-eligible", func(t *testing.T) {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        requester.ID,
			ScopeAssetID:  pg(pgAsset.ID),
			SubjectUserID: pg(user.ID),
		}); err != nil {
			t.Fatal(err)
		}
		ok, err := r.IsEligibleRequester(ctx, user.ID, dba.ID, pgAsset.ID)
		if err != nil {
			t.Fatalf("IsEligibleRequester error: %v", err)
		}
		if !ok {
			t.Fatal("IsEligibleRequester = false; want true (standing binding of requester_role)")
		}
	})
}
