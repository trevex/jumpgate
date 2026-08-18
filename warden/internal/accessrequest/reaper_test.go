package accessrequest_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/audit"
)

// grantRevoked reports whether a grant now has revoked_at set + the given reason.
func grantRevoked(t *testing.T, h *harness, gid uuid.UUID, wantReason string) bool {
	t.Helper()
	g, err := h.q.GetGrant(h.ctx, gid)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if !g.RevokedAt.Valid {
		return false
	}
	if g.RevokedReason.String != wantReason {
		t.Fatalf("revoked_reason = %q, want %q", g.RevokedReason.String, wantReason)
	}
	return true
}

func TestReapExpired(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subject := h.mkUser(t, "subj@x")

	past := h.activeGrant(t, subject, -time.Minute) // expires_at = now()-1m
	future := h.activeGrant(t, subject, time.Hour)  // expires_at = now()+1h

	// The reaper is side-effects-only: authz already treats the expired grant as
	// inactive BEFORE any sweep runs.
	if holds, _ := h.roles.HoldsRole(h.ctx, subject, h.role, "asset", h.asset); !holds {
		t.Fatal("precondition: the future grant should confer the role (holds=true)")
	}

	n, err := h.svc.ReapExpired(h.ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("ReapExpired returned %d, want 1", n)
	}

	// Past grant is now revoked with reason 'expired'; future grant untouched.
	if !grantRevoked(t, h, past, "expired") {
		t.Fatal("past grant should be revoked with reason 'expired'")
	}
	if grantRevoked(t, h, future, "expired") {
		t.Fatal("future grant must be untouched by the reaper")
	}

	// Terminator was called for the expired grant, and NOT the future one.
	if !h.term.sawGrant(past) {
		t.Fatalf("terminator not invoked for expired grant %s; calls=%v", past, h.term.calls())
	}
	if h.term.sawGrant(future) {
		t.Fatal("terminator must NOT be invoked for the future grant")
	}

	// Exactly one access_grant.expired audit entry, and the chain verifies.
	if got := h.auditEventCount(t, accessrequest.EventGrantExpired); got != 1 {
		t.Fatalf("want 1 %s audit event, got %d", accessrequest.EventGrantExpired, got)
	}
	if err := audit.New(h.pool).Verify(h.ctx); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
}

func TestReapExpiredIdempotent(t *testing.T) {
	h := setup(t, 0, pgtype.Interval{})
	subject := h.mkUser(t, "subj@x")
	h.activeGrant(t, subject, -time.Minute)

	if n, err := h.svc.ReapExpired(h.ctx); err != nil || n != 1 {
		t.Fatalf("first ReapExpired = (%d, %v), want (1, nil)", n, err)
	}
	callsAfterFirst := len(h.term.calls())

	// A second sweep finds nothing (revoked_at IS NULL excludes the row): 0 grants,
	// no extra audit entry, no extra terminator call.
	n, err := h.svc.ReapExpired(h.ctx)
	if err != nil {
		t.Fatalf("second ReapExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("second ReapExpired returned %d, want 0", n)
	}
	if got := h.auditEventCount(t, accessrequest.EventGrantExpired); got != 1 {
		t.Fatalf("want 1 %s audit event after idempotent re-run, got %d", accessrequest.EventGrantExpired, got)
	}
	if got := len(h.term.calls()); got != callsAfterFirst {
		t.Fatalf("terminator called %d times after re-run, want %d", got, callsAfterFirst)
	}
}
