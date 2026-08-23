package accessrequest_test

import (
	"context"
	"errors"
	"sync"
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
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// fakeTerminator records the grant ids it was asked to terminate.
type fakeTerminator struct {
	mu     sync.Mutex
	called []uuid.UUID
}

func (f *fakeTerminator) TerminateGrant(_ context.Context, grantID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, grantID)
	return nil
}

func (f *fakeTerminator) calls() []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uuid.UUID, len(f.called))
	copy(out, f.called)
	return out
}

func (f *fakeTerminator) sawGrant(id uuid.UUID) bool {
	for _, g := range f.calls() {
		if g == id {
			return true
		}
	}
	return false
}

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
	term  *fakeTerminator
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
		r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name, Capabilities: caps})
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
	asset, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder.ID, Name: "pg", Labels: []byte("{}"), Kind: "ssh"})
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
	term := &fakeTerminator{}
	svc := accessrequest.NewService(pool, audit.New(pool), resolver, roles, term, 8*time.Hour)

	return &harness{
		pool: pool, q: q, svc: svc, roles: roles, term: term, ctx: ctx,
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

// activeGrant mints an active JIT access_grant of the target role to userID and
// returns its id (used to test revocation).
func (h *harness) activeGrant(t *testing.T, userID uuid.UUID, expires time.Duration) uuid.UUID {
	t.Helper()
	req, err := h.q.CreateAccessRequest(h.ctx, gen.CreateAccessRequestParams{
		RequesterUserID:   userID,
		RoleID:            h.role,
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
	g, err := h.q.CreateAccessGrant(h.ctx, gen.CreateAccessGrantParams{
		RequestID:     req.ID,
		RoleID:        h.role,
		ScopeAssetID:  h.asset,
		SubjectUserID: userID,
		ExpiresAt:     time.Now().Add(expires),
	})
	if err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return g.ID
}

// drainAudit chains all queued outbox events into the audit_log so tests can
// assert on the tamper-evident chain (no background drainer runs in tests).
func (h *harness) drainAudit(t *testing.T) {
	t.Helper()
	for {
		n, err := audit.New(h.pool).DrainOnce(h.ctx, 256)
		if err != nil {
			t.Fatalf("DrainOnce: %v", err)
		}
		if n < 256 {
			return
		}
	}
}

func (h *harness) auditEventCount(t *testing.T, eventType string) int {
	t.Helper()
	h.drainAudit(t)
	rows, err := h.q.ListAuditEntries(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.EventType == eventType {
			n++
		}
	}
	return n
}

func TestRevokeGrantByAdmin(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subject := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subject, time.Hour)

	// Precondition: grant confers the role.
	if holds, _ := h.roles.HoldsRole(h.ctx, subject, h.role, "asset", h.asset); !holds {
		t.Fatal("precondition: active grant should confer the role")
	}

	admin := auth.CurrentUser{ID: h.mkUser(t, "admin@x")}
	revoked, err := h.svc.RevokeGrant(h.ctx, admin, true, gid, "cleanup")
	if err != nil {
		t.Fatalf("RevokeGrant(admin): %v", err)
	}
	if !revoked.RevokedAt.Valid {
		t.Fatal("revoked grant should have revoked_at set")
	}

	// Grant no longer confers the role.
	if holds, _ := h.roles.HoldsRole(h.ctx, subject, h.role, "asset", h.asset); holds {
		t.Fatal("revoked grant must not confer the role")
	}
	if !h.term.sawGrant(gid) {
		t.Fatalf("terminator not invoked for grant %s; calls=%v", gid, h.term.calls())
	}
	if h.auditEventCount(t, accessrequest.EventGrantRevoked) != 1 {
		t.Fatalf("want 1 %s audit event", accessrequest.EventGrantRevoked)
	}
	if err := audit.New(h.pool).Verify(h.ctx); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
}

func TestRevokeGrantBySubject(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subjID := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subjID, time.Hour)

	subject := auth.CurrentUser{ID: subjID}
	if _, err := h.svc.RevokeGrant(h.ctx, subject, false, gid, "self"); err != nil {
		t.Fatalf("self-revoke: %v", err)
	}
	if holds, _ := h.roles.HoldsRole(h.ctx, subjID, h.role, "asset", h.asset); holds {
		t.Fatal("self-revoked grant must not confer the role")
	}
	if !h.term.sawGrant(gid) {
		t.Fatal("terminator not invoked on self-revoke")
	}
}

func TestRevokeGrantByApprover(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	subjID := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subjID, time.Hour)

	// A standing approver for (role, asset) may revoke.
	approverID := h.mkUser(t, "app@x")
	h.bindStanding(t, approverID, h.approverRole)
	approver := auth.CurrentUser{ID: approverID}
	if _, err := h.svc.RevokeGrant(h.ctx, approver, false, gid, "approver revoke"); err != nil {
		t.Fatalf("approver revoke: %v", err)
	}
	if holds, _ := h.roles.HoldsRole(h.ctx, subjID, h.role, "asset", h.asset); holds {
		t.Fatal("approver-revoked grant must not confer the role")
	}
	if !h.term.sawGrant(gid) {
		t.Fatal("terminator not invoked on approver revoke")
	}
}

// TestCanReviewGrant asserts the grant-review predicate: the grant's subject and
// a standing potential approver may review; an unrelated user and a JIT-granted
// approver-role holder may not; an unknown grant fails closed (false, no error).
func TestCanReviewGrant(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	subjID := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subjID, time.Hour)

	// Subject → reviewable.
	if ok, err := h.svc.CanReviewGrant(h.ctx, subjID, gid); err != nil || !ok {
		t.Fatalf("subject CanReviewGrant = (%v, %v), want (true, nil)", ok, err)
	}

	// Standing potential approver for (role, asset) → reviewable.
	approverID := h.mkUser(t, "app@x")
	h.bindStanding(t, approverID, h.approverRole)
	if ok, err := h.svc.CanReviewGrant(h.ctx, approverID, gid); err != nil || !ok {
		t.Fatalf("approver CanReviewGrant = (%v, %v), want (true, nil)", ok, err)
	}

	// Unrelated user → not reviewable.
	stranger := h.mkUser(t, "stranger@x")
	if ok, err := h.svc.CanReviewGrant(h.ctx, stranger, gid); err != nil || ok {
		t.Fatalf("stranger CanReviewGrant = (%v, %v), want (false, nil)", ok, err)
	}

	// A JIT-granted approver-role holder is NOT a potential approver (governance is
	// standing-only) → not reviewable.
	jitApprover := h.mkUser(t, "jit-app@x")
	h.grantRole(t, jitApprover, h.approverRole)
	if ok, err := h.svc.CanReviewGrant(h.ctx, jitApprover, gid); err != nil || ok {
		t.Fatalf("JIT-approver CanReviewGrant = (%v, %v), want (false, nil)", ok, err)
	}

	// Unknown grant → fails closed (false, no error).
	if ok, err := h.svc.CanReviewGrant(h.ctx, subjID, uuid.New()); err != nil || ok {
		t.Fatalf("unknown-grant CanReviewGrant = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestRevokeGrantForbidden(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	subjID := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subjID, time.Hour)

	// An unrelated non-admin, non-approver may NOT revoke.
	stranger := auth.CurrentUser{ID: h.mkUser(t, "stranger@x")}
	if _, err := h.svc.RevokeGrant(h.ctx, stranger, false, gid, "x"); !errors.Is(err, accessrequest.ErrRevokeForbidden) {
		t.Fatalf("stranger revoke: err = %v, want ErrRevokeForbidden", err)
	}
	// Grant still active.
	if holds, _ := h.roles.HoldsRole(h.ctx, subjID, h.role, "asset", h.asset); !holds {
		t.Fatal("forbidden revoke must not affect the grant")
	}
	if len(h.term.calls()) != 0 {
		t.Fatal("terminator must not be invoked on a forbidden revoke")
	}
}

func TestRevokeGrantNotFoundAndInactive(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	admin := auth.CurrentUser{ID: h.mkUser(t, "admin@x")}

	// Unknown id → ErrGrantNotFound.
	if _, err := h.svc.RevokeGrant(h.ctx, admin, true, uuid.New(), "x"); !errors.Is(err, accessrequest.ErrGrantNotFound) {
		t.Fatalf("unknown grant: err = %v, want ErrGrantNotFound", err)
	}

	// Already-revoked → ErrGrantInactive.
	subj := h.mkUser(t, "subj@x")
	gid := h.activeGrant(t, subj, time.Hour)
	if _, err := h.svc.RevokeGrant(h.ctx, admin, true, gid, "first"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if _, err := h.svc.RevokeGrant(h.ctx, admin, true, gid, "again"); !errors.Is(err, accessrequest.ErrGrantInactive) {
		t.Fatalf("re-revoke: err = %v, want ErrGrantInactive", err)
	}
}

func TestRevokeGrantsForUserCascade(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subject := h.mkUser(t, "subj@x")
	other := h.mkUser(t, "other@x")

	// The subject has two active target-role grants (different assets share role);
	// use two grants on the same (role, asset) is blocked by nothing here since we
	// bypass the workflow with distinct requests.
	g1 := h.activeGrant(t, subject, time.Hour)
	// Give the subject standing access to a DIFFERENT role to prove it is unaffected.
	h.bindStanding(t, subject, h.approverRole)
	// The other user has an unrelated active grant that must NOT be revoked.
	gOther := h.activeGrant(t, other, time.Hour)

	adminID := h.mkUser(t, "admin@x")
	n, err := h.svc.RevokeGrantsForUser(h.ctx, adminID, subject, "user_deactivated")
	if err != nil {
		t.Fatalf("RevokeGrantsForUser: %v", err)
	}
	if n != 1 {
		t.Fatalf("revoked count = %d, want 1", n)
	}
	// Subject's grant no longer confers the role.
	if holds, _ := h.roles.HoldsRole(h.ctx, subject, h.role, "asset", h.asset); holds {
		t.Fatal("subject's grant should be revoked")
	}
	// Subject's STANDING approver_role access is unaffected.
	if holds, _ := h.roles.HoldsRoleStanding(h.ctx, subject, h.approverRole, "asset", h.asset); !holds {
		t.Fatal("standing access must survive grant revocation")
	}
	// The other user's grant is untouched.
	if holds, _ := h.roles.HoldsRole(h.ctx, other, h.role, "asset", h.asset); !holds {
		t.Fatal("other user's grant must be unaffected")
	}
	if !h.term.sawGrant(g1) {
		t.Fatal("terminator not invoked for the revoked grant")
	}
	if h.term.sawGrant(gOther) {
		t.Fatal("terminator wrongly invoked for another user's grant")
	}
	if h.auditEventCount(t, accessrequest.EventGrantRevoked) != 1 {
		t.Fatalf("want 1 %s audit event per revoked grant", accessrequest.EventGrantRevoked)
	}
	_ = g1
}

func TestListMyGrantsAndListGrants(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subject := h.mkUser(t, "subj@x")
	admin := auth.CurrentUser{ID: h.mkUser(t, "admin@x")}

	active := h.activeGrant(t, subject, time.Hour)
	revoked := h.activeGrant(t, subject, time.Hour)
	if _, err := h.svc.RevokeGrant(h.ctx, admin, true, revoked, "x"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	mine, err := h.svc.ListMyGrants(h.ctx, subject)
	if err != nil {
		t.Fatalf("ListMyGrants: %v", err)
	}
	if len(mine) != 2 {
		t.Fatalf("ListMyGrants len = %d, want 2", len(mine))
	}
	got := map[uuid.UUID]bool{}
	for _, g := range mine {
		got[g.ID] = g.Active
	}
	if !got[active] {
		t.Fatal("active grant should have Active=true")
	}
	if got[revoked] {
		t.Fatal("revoked grant should have Active=false")
	}

	// Admin ListGrants (all) sees both; active_only sees one.
	all, err := h.svc.ListGrants(h.ctx, accessrequest.GrantFilter{Subject: subject})
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListGrants(all) len = %d, want 2", len(all))
	}
	activeOnly, err := h.svc.ListGrants(h.ctx, accessrequest.GrantFilter{Subject: subject, ActiveOnly: true})
	if err != nil {
		t.Fatalf("ListGrants(active): %v", err)
	}
	if len(activeOnly) != 1 || activeOnly[0].ID != active {
		t.Fatalf("ListGrants(active) = %+v, want [%s]", activeOnly, active)
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

	h.drainAudit(t)

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

// TestRequestAccessEnqueuesBeforeDrain proves audit events ride the outbox: after
// a self-service RequestAccess the hash-chained audit_log is still empty, and only
// after an explicit drain do the events appear (and the chain verifies).
func TestRequestAccessEnqueuesBeforeDrain(t *testing.T) {
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

	// The events are in the outbox, NOT yet in the hash-chained log.
	rows, err := h.q.ListAuditEntries(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("audit_log should be empty before drain; got %d entries", len(rows))
	}

	// Drain the outbox into the chain, then the events must be present.
	h.drainAudit(t)
	got := map[string]bool{}
	rows, err = h.q.ListAuditEntries(h.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	for _, r := range rows {
		got[r.EventType] = true
	}
	for _, want := range []string{
		accessrequest.EventRequestCreated,
		accessrequest.EventGrantActivated,
	} {
		if !got[want] {
			t.Fatalf("missing audit event %q after drain; got %v", want, got)
		}
	}
	if err := audit.New(h.pool).Verify(h.ctx); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
}
