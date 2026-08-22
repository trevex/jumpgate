package accessrequest_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
)

// TestCanReadForRequest verifies the request-party read predicate: a caller may
// read an asset/role iff they are party (requester or standing approver) to a
// PENDING access request referencing it.
func TestCanReadForRequest(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	approver := h.mkUser(t, "app@x")
	stranger := h.mkUser(t, "stranger@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, approver, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "need it")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if req.Status != "pending" {
		t.Fatalf("status = %q, want pending", req.Status)
	}

	check := func(who string, caller uuid.UUID, kind accessrequest.ReqEntityKind, id uuid.UUID, want bool) {
		t.Helper()
		got, err := h.svc.CanReadForRequest(h.ctx, caller, kind, id)
		if err != nil {
			t.Fatalf("CanReadForRequest(%s): %v", who, err)
		}
		if got != want {
			t.Fatalf("CanReadForRequest(%s, kind=%d) = %v, want %v", who, kind, got, want)
		}
	}

	// Standing approver → party to the pending request on both entities.
	check("approver/asset", approver, accessrequest.ReqEntityAsset, h.asset, true)
	check("approver/role", approver, accessrequest.ReqEntityRole, h.role, true)

	// Requester → party to their own request on both entities.
	check("requester/asset", requester, accessrequest.ReqEntityAsset, h.asset, true)
	check("requester/role", requester, accessrequest.ReqEntityRole, h.role, true)

	// Unrelated user → not party.
	check("stranger/asset", stranger, accessrequest.ReqEntityAsset, h.asset, false)
	check("stranger/role", stranger, accessrequest.ReqEntityRole, h.role, false)

	// Resolve the request (approve to threshold=1) → no longer pending → both false.
	if _, err := h.svc.Approve(h.ctx, approver, req.ID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	check("approver/asset after resolve", approver, accessrequest.ReqEntityAsset, h.asset, false)
	check("approver/role after resolve", approver, accessrequest.ReqEntityRole, h.role, false)
	check("requester/asset after resolve", requester, accessrequest.ReqEntityAsset, h.asset, false)
	check("requester/role after resolve", requester, accessrequest.ReqEntityRole, h.role, false)
}

// TestCanReadForRequestDeactivated proves the invariant that a deactivated party
// (requester or approver) can never read via this predicate — deactivation
// excludes them from IsApprover, and a deactivated requester is treated as no
// party either.
func TestCanReadForRequestDeactivated(t *testing.T) {
	h := setup(t, 1, pgtype.Interval{})
	requester := h.mkUser(t, "req@x")
	approver := h.mkUser(t, "app@x")
	h.bindStanding(t, requester, h.requesterRole)
	h.bindStanding(t, approver, h.approverRole)

	req, err := h.svc.RequestAccess(h.ctx, requester, h.role, h.asset, time.Hour, "need it")
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if req.Status != "pending" {
		t.Fatalf("status = %q, want pending", req.Status)
	}

	// Sanity: both are party while active.
	if ok, err := h.svc.CanReadForRequest(h.ctx, approver, accessrequest.ReqEntityAsset, h.asset); err != nil || !ok {
		t.Fatalf("precondition approver party: ok=%v err=%v", ok, err)
	}

	// Deactivate the approver → IsApprover excludes them → false on both entities.
	if err := h.q.DeactivateUser(h.ctx, approver); err != nil {
		t.Fatalf("DeactivateUser(approver): %v", err)
	}
	if ok, err := h.svc.CanReadForRequest(h.ctx, approver, accessrequest.ReqEntityAsset, h.asset); err != nil || ok {
		t.Fatalf("deactivated approver/asset = %v (err %v), want false", ok, err)
	}
	if ok, err := h.svc.CanReadForRequest(h.ctx, approver, accessrequest.ReqEntityRole, h.role); err != nil || ok {
		t.Fatalf("deactivated approver/role = %v (err %v), want false", ok, err)
	}

	// Deactivate the requester → no party either.
	if err := h.q.DeactivateUser(h.ctx, requester); err != nil {
		t.Fatalf("DeactivateUser(requester): %v", err)
	}
	if ok, err := h.svc.CanReadForRequest(h.ctx, requester, accessrequest.ReqEntityAsset, h.asset); err != nil || ok {
		t.Fatalf("deactivated requester/asset = %v (err %v), want false", ok, err)
	}
	if ok, err := h.svc.CanReadForRequest(h.ctx, requester, accessrequest.ReqEntityRole, h.role); err != nil || ok {
		t.Fatalf("deactivated requester/role = %v (err %v), want false", ok, err)
	}
}
