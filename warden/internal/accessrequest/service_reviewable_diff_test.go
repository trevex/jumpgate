package accessrequest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
)

// legacyReviewable is the pre-set-based ListReviewableGrantsPaged filter: per grant,
// reviewable iff the caller is the subject OR a standing approver of its (role, asset).
// The frozen reference the set-based reviewableGrants is differentially checked against.
func legacyReviewable(t *testing.T, pool *pgxpool.Pool, caller uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	ctx := context.Background()
	resolver := approvals.New(pool)
	rows, err := pool.Query(ctx, `SELECT id, role_id, scope_asset_id, subject_user_id FROM access_grants`)
	if err != nil {
		t.Fatalf("legacy grants: %v", err)
	}
	type grow struct{ id, role, asset, subject uuid.UUID }
	var gs []grow
	for rows.Next() {
		var g grow
		if err := rows.Scan(&g.id, &g.role, &g.asset, &g.subject); err != nil {
			rows.Close()
			t.Fatalf("scan grant: %v", err)
		}
		gs = append(gs, g)
	}
	rows.Close()
	out := map[uuid.UUID]bool{}
	for _, g := range gs {
		if g.subject == caller {
			out[g.id] = true
			continue
		}
		ok, err := resolver.IsApprover(ctx, caller, g.role, g.asset)
		if err != nil {
			t.Fatalf("legacy IsApprover: %v", err)
		}
		if ok {
			out[g.id] = true
		}
	}
	return out
}

func newReviewable(t *testing.T, h *harness, caller uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	rows, _, err := h.svc.ListReviewableGrantsPaged(h.ctx, caller, accessrequest.PageParams{Limit: 1000})
	if err != nil {
		t.Fatalf("ListReviewableGrantsPaged: %v", err)
	}
	out := map[uuid.UUID]bool{}
	for _, g := range rows {
		out[g.ID] = true
	}
	return out
}

func requireSameSet(t *testing.T, label string, want, got map[uuid.UUID]bool) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: size differs legacy=%d new=%d\n legacy=%v\n new=%v", label, len(want), len(got), want, got)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("%s: new missing grant %s", label, id)
		}
	}
}

// TestListReviewableGrantsMatchesLegacy differentially checks the set-based
// reviewableGrants against the per-row loop across every review mechanism — the
// subject-self arm (including a DEACTIVATED subject, who still reviews their own
// grant), the approver-role arm, an explicit approver subject, a nested-group subject,
// plus a non-reviewer and a deactivated approver (who reviews nothing).
func TestListReviewableGrantsMatchesLegacy(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	pol := policyID(t, h)

	subjA := h.mkUser(t, "r-subjA@x")
	subjB := h.mkUser(t, "r-subjB@x")
	h.activeGrant(t, subjA, time.Hour)
	h.activeGrant(t, subjB, time.Hour)

	roleApprover := h.mkUser(t, "r-role@x") // reviews via approver_role arm
	h.bindStanding(t, roleApprover, h.approverRole)

	subjApprover := h.mkUser(t, "r-subj-approver@x") // explicit approver subject
	addApproverUser(t, h, pol, subjApprover)

	grpApprover := h.mkUser(t, "r-grp@x") // approver via nested group subject
	inner := mkGroup(t, h, "r-inner")
	outer := mkGroup(t, h, "r-outer")
	addUserToGroup(t, h, inner, grpApprover)
	nestGroup(t, h, outer, inner)
	addApproverGroup(t, h, pol, outer)

	nonReviewer := h.mkUser(t, "r-non@x")
	deactApprover := h.mkUser(t, "r-deact@x")
	h.bindStanding(t, deactApprover, h.approverRole)

	// Deactivate a subject (must STILL review their own grant — subject arm has no
	// active check) and an approver (must review NOTHING — approver arm needs active).
	if err := h.q.DeactivateUser(h.ctx, subjA); err != nil {
		t.Fatalf("deactivate subjA: %v", err)
	}
	if err := h.q.DeactivateUser(h.ctx, deactApprover); err != nil {
		t.Fatalf("deactivate approver: %v", err)
	}

	for _, c := range []struct {
		name string
		id   uuid.UUID
	}{
		{"subjA(deactivated,own)", subjA},
		{"subjB", subjB},
		{"roleApprover", roleApprover},
		{"subjApprover", subjApprover},
		{"grpApprover", grpApprover},
		{"nonReviewer", nonReviewer},
		{"deactApprover", deactApprover},
	} {
		requireSameSet(t, c.name, legacyReviewable(t, h.pool, c.id), newReviewable(t, h, c.id))
	}
}
