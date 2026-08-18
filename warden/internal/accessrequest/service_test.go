package accessrequest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
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

// harness bundles a service + the seeded fixture ids for a scenario.
type harness struct {
	pool  *pgxpool.Pool
	q     *gen.Queries
	svc   *accessrequest.Service
	roles *authz.RoleResolver
	ctx   context.Context

	asset uuid.UUID
	role  uuid.UUID // the requestable target role

	requesterRole uuid.UUID
	approverRole  uuid.UUID
}

// setup builds a service and a base fixture: one folder+asset, a target role, a
// requester_role and approver_role, and a request policy with requiredApprovals
// (and optional maxDuration). It returns the harness; callers bind users.
func setup(t *testing.T, requiredApprovals int32, maxDuration pgtype.Interval) *harness {
	t.Helper()
	pool := newPool(t)
	ctx := context.Background()
	q := gen.New(pool)
	caps := []byte("[]")

	mkRole := func(name string) uuid.UUID {
		r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name, ResourceType: "asset", Capabilities: caps})
		if err != nil {
			t.Fatalf("CreateRole(%s): %v", name, err)
		}
		return r.ID
	}
	target := mkRole("db_admin")
	requesterRole := mkRole("requester")
	approverRole := mkRole("approver")

	folder, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}")})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID:            target,
		RequiredApprovals: requiredApprovals,
		ApproverRoleID:    pg(approverRole),
		RequesterRoleID:   pg(requesterRole),
		MaxDuration:       maxDuration,
	}); err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	resolver := approvals.New(pool)
	roles := authz.NewRoleResolver(pool)
	svc := accessrequest.NewService(pool, audit.New(pool), resolver, roles, 8*time.Hour)

	return &harness{
		pool: pool, q: q, svc: svc, roles: roles, ctx: ctx,
		asset: asset.ID, role: target,
		requesterRole: requesterRole, approverRole: approverRole,
	}
}

func (h *harness) mkUser(t *testing.T, email string) uuid.UUID {
	t.Helper()
	u, err := h.q.CreateUser(h.ctx, gen.CreateUserParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u.ID
}

// bindStanding grants roleID to userID on the asset via a standing role_binding.
func (h *harness) bindStanding(t *testing.T, userID, roleID uuid.UUID) {
	t.Helper()
	if _, err := h.q.CreateRoleBinding(h.ctx, gen.CreateRoleBindingParams{
		RoleID:        roleID,
		ScopeAssetID:  pg(h.asset),
		SubjectUserID: pg(userID),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// grantRole mints an active JIT access_grant of roleID to userID (bypasses the
// workflow), to test the T2.5 governance rule that a granted role gives access
// but NOT eligibility/approver standing.
func (h *harness) grantRole(t *testing.T, userID, roleID uuid.UUID) {
	t.Helper()
	// Create a dummy request to satisfy the grant's request_id FK.
	req, err := h.q.CreateAccessRequest(h.ctx, gen.CreateAccessRequestParams{
		RequesterUserID:   userID,
		RoleID:            roleID,
		AssetID:           h.asset,
		Reason:            "seed",
		RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		RequiredApprovals: 0,
		GrantedDuration:   pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		Status:            "granted",
	})
	if err != nil {
		t.Fatalf("seed grant request: %v", err)
	}
	if _, err := h.q.CreateAccessGrant(h.ctx, gen.CreateAccessGrantParams{
		RequestID:     req.ID,
		RoleID:        roleID,
		ScopeAssetID:  h.asset,
		SubjectUserID: userID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

func TestTwoApprovalFlow(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	a1 := h.mkUser(t, "a1@x")
	a2 := h.mkUser(t, "a2@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, a1, h.approverRole)
	h.bindStanding(t, a2, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "need it")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if req.Status != "pending" {
		t.Fatalf("status = %q, want pending", req.Status)
	}

	// First approval → still pending.
	after1, err := h.svc.Approve(h.ctx, a1, req.ID)
	if err != nil {
		t.Fatalf("Approve a1: %v", err)
	}
	if after1.Status != "pending" {
		t.Fatalf("after 1 approval: status = %q, want pending", after1.Status)
	}

	// Second DISTINCT approver → granted + grant minted.
	before := time.Now()
	after2, err := h.svc.Approve(h.ctx, a2, req.ID)
	if err != nil {
		t.Fatalf("Approve a2: %v", err)
	}
	if after2.Status != "granted" {
		t.Fatalf("after 2 approvals: status = %q, want granted", after2.Status)
	}
	if after2.GrantID == uuid.Nil {
		t.Fatal("expected a grant id after threshold")
	}
	grant, err := h.q.GetGrant(h.ctx, after2.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	wantExp := before.Add(time.Hour)
	if d := grant.ExpiresAt.Sub(wantExp); d < -30*time.Second || d > 30*time.Second {
		t.Fatalf("expires_at = %v, want ≈ %v", grant.ExpiresAt, wantExp)
	}
	// Grant confers access.
	holds, err := h.roles.HoldsRole(h.ctx, requester, h.role, "asset", h.asset)
	if err != nil {
		t.Fatalf("HoldsRole: %v", err)
	}
	if !holds {
		t.Fatal("requester should hold the role via the active grant")
	}
}

func TestSelfService(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	h.bindStanding(t, requester, h.requesterRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "self")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if req.Status != "granted" {
		t.Fatalf("status = %q, want granted", req.Status)
	}
	if req.GrantID == uuid.Nil {
		t.Fatal("self-service should mint a grant immediately")
	}
	holds, _ := h.roles.HoldsRole(h.ctx, requester, h.role, "asset", h.asset)
	if !holds {
		t.Fatal("self-service grant should confer access")
	}
}

func TestDenyThenApprove(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	a1 := h.mkUser(t, "a1@x")
	a2 := h.mkUser(t, "a2@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, a1, h.approverRole)
	h.bindStanding(t, a2, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	denied, err := h.svc.Deny(h.ctx, a1, req.ID)
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if denied.Status != "denied" {
		t.Fatalf("status = %q, want denied", denied.Status)
	}
	if _, err := h.svc.Approve(h.ctx, a2, req.ID); !errors.Is(err, accessrequest.ErrNotPending) {
		t.Fatalf("Approve after deny: err = %v, want ErrNotPending", err)
	}
}

func TestSelfApproveAndDoubleVote(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	a1 := h.mkUser(t, "a1@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, a1, h.approverRole)
	// Make the requester also an approver so the self-approve check (not
	// the not-approver check) is what fires.
	h.bindStanding(t, requester, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if _, err := h.svc.Approve(h.ctx, requester, req.ID); !errors.Is(err, accessrequest.ErrSelfApprove) {
		t.Fatalf("self-approve: err = %v, want ErrSelfApprove", err)
	}
	if _, err := h.svc.Approve(h.ctx, a1, req.ID); err != nil {
		t.Fatalf("Approve a1: %v", err)
	}
	if _, err := h.svc.Approve(h.ctx, a1, req.ID); !errors.Is(err, accessrequest.ErrAlreadyVoted) {
		t.Fatalf("double-vote: err = %v, want ErrAlreadyVoted", err)
	}
}

func TestDuplicatePendingAndAlreadyActive(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	h.bindStanding(t, requester, h.requesterRole)

	if _, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x"); err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	// Duplicate pending → ErrDuplicatePending.
	if _, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x"); !errors.Is(err, accessrequest.ErrDuplicatePending) {
		t.Fatalf("dup pending: err = %v, want ErrDuplicatePending", err)
	}

	// Standing holder of the target role → ErrAlreadyActive.
	standingUser := h.mkUser(t, "standing@x")
	h.bindStanding(t, standingUser, h.requesterRole)
	h.bindStanding(t, standingUser, h.role)
	if _, err := h.svc.RequestAccess(h.ctx, standingUser, h.role, h.asset, time.Hour, "x"); !errors.Is(err, accessrequest.ErrAlreadyActive) {
		t.Fatalf("standing already-active: err = %v, want ErrAlreadyActive", err)
	}

	// Holder via an active JIT grant of the target role → also ErrAlreadyActive.
	grantedUser := h.mkUser(t, "granted@x")
	h.bindStanding(t, grantedUser, h.requesterRole)
	h.grantRole(t, grantedUser, h.role)
	if _, err := h.svc.RequestAccess(h.ctx, grantedUser, h.role, h.asset, time.Hour, "x"); !errors.Is(err, accessrequest.ErrAlreadyActive) {
		t.Fatalf("grant already-active: err = %v, want ErrAlreadyActive", err)
	}
}

func TestDurationClamp(t *testing.T) {
	// policy max_duration = 1h; request 720h → grant expires ≈ now()+1h.
	oneHour := pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true}
	h := setup(t, 0, oneHour)
	requester := h.mkUser(t, "req@x")
	h.bindStanding(t, requester, h.requesterRole)

	before := time.Now()
	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, 720*time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	grant, err := h.q.GetGrant(h.ctx, req.GrantID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	wantExp := before.Add(time.Hour)
	if d := grant.ExpiresAt.Sub(wantExp); d < -30*time.Second || d > 30*time.Second {
		t.Fatalf("clamped expires_at = %v, want ≈ %v (now+1h)", grant.ExpiresAt, wantExp)
	}
}

func TestIneligibleRequester(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})

	// No standing requester_role, not a requester subject → ErrNotEligible.
	stranger := h.mkUser(t, "stranger@x")
	if _, err := h.svc.RequestAccess(h.ctx, stranger, h.role, h.asset, time.Hour, "x"); !errors.Is(err, accessrequest.ErrNotEligible) {
		t.Fatalf("stranger: err = %v, want ErrNotEligible", err)
	}

	// Eligible ONLY via a JIT grant of the requester_role → still ErrNotEligible
	// (T2.5 governance: grants confer access, not governance eligibility).
	grantedReq := h.mkUser(t, "grantedreq@x")
	h.grantRole(t, grantedReq, h.requesterRole)
	// sanity: the grant DOES confer HoldsRole on requester_role.
	if holds, _ := h.roles.HoldsRole(h.ctx, grantedReq, h.requesterRole, "asset", h.asset); !holds {
		t.Fatal("precondition: granted requester_role should be held (access)")
	}
	if _, err := h.svc.RequestAccess(h.ctx, grantedReq, h.role, h.asset, time.Hour, "x"); !errors.Is(err, accessrequest.ErrNotEligible) {
		t.Fatalf("granted-only requester: err = %v, want ErrNotEligible", err)
	}
}

func TestApproverGovernance(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	h.bindStanding(t, requester, h.requesterRole)
	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}

	// Non-approver → ErrNotApprover.
	nobody := h.mkUser(t, "nobody@x")
	if _, err := h.svc.Approve(h.ctx, nobody, req.ID); !errors.Is(err, accessrequest.ErrNotApprover) {
		t.Fatalf("non-approver: err = %v, want ErrNotApprover", err)
	}

	// Approver_role ONLY via a JIT grant → ErrNotApprover (T2.5).
	grantedApp := h.mkUser(t, "grantedapp@x")
	h.grantRole(t, grantedApp, h.approverRole)
	if holds, _ := h.roles.HoldsRole(h.ctx, grantedApp, h.approverRole, "asset", h.asset); !holds {
		t.Fatal("precondition: granted approver_role should be held (access)")
	}
	if _, err := h.svc.Approve(h.ctx, grantedApp, req.ID); !errors.Is(err, accessrequest.ErrNotApprover) {
		t.Fatalf("granted-only approver: err = %v, want ErrNotApprover", err)
	}

	// Standing approver → succeeds (required_approvals=1 → granted).
	standingApp := h.mkUser(t, "standingapp@x")
	h.bindStanding(t, standingApp, h.approverRole)
	out, err := h.svc.Approve(h.ctx, standingApp, req.ID)
	if err != nil {
		t.Fatalf("standing approver Approve: %v", err)
	}
	if out.Status != "granted" {
		t.Fatalf("status = %q, want granted", out.Status)
	}
}

func TestListPendingApprovals(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	approver := h.mkUser(t, "app@x")
	nonApprover := h.mkUser(t, "non@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, approver, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}

	// Eligible approver sees it.
	rows, err := h.svc.ListPendingApprovals(h.ctx, approver)
	if err != nil {
		t.Fatalf("ListPendingApprovals(approver): %v", err)
	}
	if len(rows) != 1 || rows[0].ID != req.ID {
		t.Fatalf("approver pending = %+v, want [%s]", rows, req.ID)
	}

	// Non-approver sees nothing.
	rows, err = h.svc.ListPendingApprovals(h.ctx, nonApprover)
	if err != nil {
		t.Fatalf("ListPendingApprovals(non): %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("non-approver pending = %+v, want empty", rows)
	}

	// The requester does not see their own request (even if also an approver).
	h.bindStanding(t, requester, h.approverRole)
	rows, err = h.svc.ListPendingApprovals(h.ctx, requester)
	if err != nil {
		t.Fatalf("ListPendingApprovals(requester): %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("requester pending = %+v, want empty (own excluded)", rows)
	}
}

func TestCancel(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	other := h.mkUser(t, "other@x")
	h.bindStanding(t, requester, h.requesterRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	// A non-requester cannot cancel.
	if err := h.svc.Cancel(h.ctx, other, req.ID); !errors.Is(err, accessrequest.ErrNotRequester) {
		t.Fatalf("other cancel: err = %v, want ErrNotRequester", err)
	}
	if err := h.svc.Cancel(h.ctx, requester, req.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	// Cancelling again → ErrNotPending.
	if err := h.svc.Cancel(h.ctx, requester, req.ID); !errors.Is(err, accessrequest.ErrNotPending) {
		t.Fatalf("re-cancel: err = %v, want ErrNotPending", err)
	}
}

func TestAuditChain(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	approver := h.mkUser(t, "app@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, approver, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if _, err := h.svc.Approve(h.ctx, approver, req.ID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	log := audit.New(h.pool)
	if err := log.Verify(h.ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}

	// Expected event types present.
	rows, err := h.q.ListAuditEntries(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.EventType] = true
	}
	for _, want := range []string{
		accessrequest.EventRequestCreated,
		accessrequest.EventRequestApproved,
		accessrequest.EventGrantActivated,
	} {
		if !got[want] {
			t.Fatalf("missing audit event %q; got %v", want, got)
		}
	}
}
