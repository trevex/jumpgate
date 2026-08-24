package accessrequest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// legacyListPending is the pre-set-based implementation of ListPendingApprovals: the
// per-row loop (ListPendingRequests → IsApprover → CountApprovals). It is the frozen
// reference the set-based approvablePending is differentially checked against.
func legacyListPending(t *testing.T, pool *pgxpool.Pool, caller uuid.UUID) map[uuid.UUID]int {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)
	resolver := approvals.New(pool)
	rows, err := q.ListPendingRequests(ctx)
	if err != nil {
		t.Fatalf("legacy list pending: %v", err)
	}
	out := map[uuid.UUID]int{}
	for _, r := range rows {
		if r.RequesterUserID == caller {
			continue
		}
		ok, err := resolver.IsApprover(ctx, caller, r.RoleID, r.AssetID)
		if err != nil {
			t.Fatalf("legacy IsApprover: %v", err)
		}
		if !ok {
			continue
		}
		c, err := q.CountApprovals(ctx, r.ID)
		if err != nil {
			t.Fatalf("legacy CountApprovals: %v", err)
		}
		out[r.ID] = int(c)
	}
	return out
}

func newListPending(t *testing.T, h *harness, caller uuid.UUID) map[uuid.UUID]int {
	t.Helper()
	rows, err := h.svc.ListPendingApprovals(h.ctx, caller)
	if err != nil {
		t.Fatalf("ListPendingApprovals: %v", err)
	}
	out := map[uuid.UUID]int{}
	for _, r := range rows {
		out[r.ID] = r.ApprovalsSoFar
	}
	return out
}

func requireSamePending(t *testing.T, label string, want, got map[uuid.UUID]int) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: set size differs: legacy=%d new=%d\n legacy=%v\n new=%v", label, len(want), len(got), want, got)
	}
	for id, n := range want {
		gn, ok := got[id]
		if !ok {
			t.Fatalf("%s: new missing request %s (legacy count %d)", label, id, n)
		}
		if gn != n {
			t.Fatalf("%s: request %s approve-count legacy=%d new=%d", label, id, n, gn)
		}
	}
}

// policyID returns the id of the global default policy for h.role.
func policyID(t *testing.T, h *harness) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := h.pool.QueryRow(h.ctx,
		`SELECT id FROM request_policies WHERE role_id = $1 AND scope_folder_id IS NULL AND scope_asset_id IS NULL`,
		h.role).Scan(&id); err != nil {
		t.Fatalf("policyID: %v", err)
	}
	return id
}

func addApproverUser(t *testing.T, h *harness, policy, user uuid.UUID) {
	t.Helper()
	if _, err := h.pool.Exec(h.ctx,
		`INSERT INTO request_policy_subjects(policy_id, kind, subject_user_id) VALUES($1,'approver',$2)`,
		policy, user); err != nil {
		t.Fatalf("addApproverUser: %v", err)
	}
}

func addApproverGroup(t *testing.T, h *harness, policy, group uuid.UUID) {
	t.Helper()
	if _, err := h.pool.Exec(h.ctx,
		`INSERT INTO request_policy_subjects(policy_id, kind, subject_group_id) VALUES($1,'approver',$2)`,
		policy, group); err != nil {
		t.Fatalf("addApproverGroup: %v", err)
	}
}

func mkGroup(t *testing.T, h *harness, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := h.pool.QueryRow(h.ctx, `INSERT INTO groups(name) VALUES($1) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("mkGroup: %v", err)
	}
	return id
}

func addUserToGroup(t *testing.T, h *harness, group, user uuid.UUID) {
	t.Helper()
	if _, err := h.pool.Exec(h.ctx, `INSERT INTO group_memberships(group_id, member_user_id) VALUES($1,$2)`, group, user); err != nil {
		t.Fatalf("addUserToGroup: %v", err)
	}
}

func nestGroup(t *testing.T, h *harness, parent, member uuid.UUID) {
	t.Helper()
	if _, err := h.pool.Exec(h.ctx, `INSERT INTO group_memberships(group_id, member_group_id) VALUES($1,$2)`, parent, member); err != nil {
		t.Fatalf("nestGroup: %v", err)
	}
}

// TestListPendingApprovalsMatchesLegacy differentially checks the set-based
// approvablePending against the per-row IsApprover loop across every approver
// mechanism — the approver-role arm, an explicit user subject, a nested-group
// subject, plus exclusions (own request, non-approver, deactivated) — with a
// non-zero approval count in the mix.
func TestListPendingApprovalsMatchesLegacy(t *testing.T) {
	h := setup(t, 2, pgtype.Interval{}) // requiredApprovals=2 → a single vote keeps it pending
	pol := policyID(t, h)

	requester := h.mkUser(t, "d-requester@x")
	h.bindStanding(t, requester, h.requesterRole)

	roleApprover := h.mkUser(t, "d-role-approver@x") // approver via approver_role arm
	h.bindStanding(t, roleApprover, h.approverRole)

	subjApprover := h.mkUser(t, "d-subj-approver@x") // explicit approver subject
	addApproverUser(t, h, pol, subjApprover)

	grpApprover := h.mkUser(t, "d-grp-approver@x") // approver via nested group subject
	inner := mkGroup(t, h, "d-inner")
	outer := mkGroup(t, h, "d-outer")
	addUserToGroup(t, h, inner, grpApprover)
	nestGroup(t, h, outer, inner) // grpApprover ∈ inner ∈ outer
	addApproverGroup(t, h, pol, outer)

	nonApprover := h.mkUser(t, "d-non@x")
	deactApprover := h.mkUser(t, "d-deact@x")
	h.bindStanding(t, deactApprover, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	// One recorded approval so the compared approve-count is non-zero (2 required, so
	// still pending).
	if _, err := h.q.AddApproval(h.ctx, gen.AddApprovalParams{
		RequestID: req.ID, ApproverUserID: roleApprover, Decision: "approve",
	}); err != nil {
		t.Fatalf("AddApproval: %v", err)
	}
	// Deactivate the deactivated approver AFTER seeding.
	if err := h.q.DeactivateUser(h.ctx, deactApprover); err != nil {
		t.Fatalf("DeactivateUser: %v", err)
	}

	for _, caller := range []struct {
		name string
		id   uuid.UUID
	}{
		{"roleApprover", roleApprover},
		{"subjApprover", subjApprover},
		{"grpApprover", grpApprover},
		{"nonApprover", nonApprover},
		{"requester", requester},
		{"deactivated", deactApprover},
	} {
		requireSamePending(t, caller.name,
			legacyListPending(t, h.pool, caller.id),
			newListPending(t, h, caller.id))
	}
}

// TestListPendingApprovalsPrecedenceMatchesLegacy checks the set-based effective-policy
// precedence: an asset-scoped policy override with a DIFFERENT approver must win over
// the global default, for both the new and legacy paths.
func TestListPendingApprovalsPrecedenceMatchesLegacy(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})

	requester := h.mkUser(t, "p-requester@x")
	h.bindStanding(t, requester, h.requesterRole)

	globalApprover := h.mkUser(t, "p-global@x")
	h.bindStanding(t, globalApprover, h.approverRole)

	// Asset-scoped override policy for the same role, with an explicit approver subject
	// and no approver_role. Its presence must make the asset-scoped rule effective, so
	// the global approver no longer qualifies and the override's subject does.
	overrideApprover := h.mkUser(t, "p-override@x")
	var overrideID uuid.UUID
	if err := h.pool.QueryRow(h.ctx,
		`INSERT INTO request_policies(role_id, scope_asset_id, required_approvals) VALUES($1,$2,1) RETURNING id`,
		h.role, h.asset).Scan(&overrideID); err != nil {
		t.Fatalf("override policy: %v", err)
	}
	addApproverUser(t, h, overrideID, overrideApprover)
	// The override shadows the global policy for eligibility too, so make the requester
	// an explicit requester subject on the override or RequestAccess is (correctly) denied.
	if _, err := h.pool.Exec(h.ctx,
		`INSERT INTO request_policy_subjects(policy_id, kind, subject_user_id) VALUES($1,'requester',$2)`,
		overrideID, requester); err != nil {
		t.Fatalf("override requester subject: %v", err)
	}

	if _, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "x"); err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}

	for _, caller := range []struct {
		name string
		id   uuid.UUID
	}{
		{"globalApprover(shadowed)", globalApprover},
		{"overrideApprover", overrideApprover},
	} {
		want := legacyListPending(t, h.pool, caller.id)
		got := newListPending(t, h, caller.id)
		requireSamePending(t, caller.name, want, got)
	}
	// Sanity: the two callers must genuinely differ (override wins), else the test is
	// vacuous. The override approver sees the request; the global (shadowed) one does not.
	if len(newListPending(t, h, globalApprover)) != 0 {
		t.Fatal("expected global approver to be shadowed by the asset-scoped override")
	}
	if len(newListPending(t, h, overrideApprover)) != 1 {
		t.Fatal("expected override approver to see the request")
	}
}
