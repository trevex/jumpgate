package rpc_test

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// TestDeleteRoleCascade proves the DeleteRole cascade removes every reference to a
// role in one transaction: its bindings, both directions of its role-grant edges,
// the request policies for which it is the requestable role (and their subjects),
// and its active grants (revoked so the sweep tears down the live sessions they
// authorized). A policy referencing the role only as an approver SURVIVES with that
// column NULLed. A missing role is NotFound.
func TestDeleteRoleCascade(t *testing.T) {
	f := setupCascade(t)
	ctx := f.ctx
	q := f.q

	// R: the role under deletion, bound to the subject user on the asset (via the
	// public API so the standing binding is real and drives the sweep). It carries
	// ssh:login:deploy so the seeded live session is authorized while it stands.
	roleID := f.createRole(t, "ssh-deploy")
	rUUID := uuid.MustParse(roleID)
	bindingID := f.bindRoleOnAsset(t, roleID)
	_ = bindingID

	// A source role S and a second role O, seeded directly.
	src, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "src-role", Capabilities: []byte("[]")})
	if err != nil {
		t.Fatalf("CreateRole src: %v", err)
	}
	other, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: "other-role", Capabilities: []byte("[]")})
	if err != nil {
		t.Fatalf("CreateRole other: %v", err)
	}

	// Two role-grant edges: R as the conferred role_id (S confers R), and R as the
	// source that confers O. Both directions must vanish.
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: rUUID, SourceRoleID: src.ID, Via: "same_object"}); err != nil {
		t.Fatalf("CreateRoleGrant R<-S: %v", err)
	}
	if _, err := q.CreateRoleGrant(ctx, gen.CreateRoleGrantParams{RoleID: other.ID, SourceRoleID: rUUID, Via: "same_object"}); err != nil {
		t.Fatalf("CreateRoleGrant O<-R: %v", err)
	}

	// P1: a request policy whose requestable role is R, plus a subject. Both go.
	p1, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: rUUID, RequiredApprovals: 1, Name: pgtype.Text{String: "p1", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateRequestPolicy p1: %v", err)
	}
	if _, err := q.AddPolicySubject(ctx, gen.AddPolicySubjectParams{
		PolicyID: p1.ID, Kind: "requester", SubjectUserID: pgtype.UUID{Bytes: f.user, Valid: true},
	}); err != nil {
		t.Fatalf("AddPolicySubject p1: %v", err)
	}

	// P2: a request policy for a DIFFERENT role (O) that references R only as its
	// approver role. It must SURVIVE with approver_role_id NULLed.
	p2, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: other.ID, RequiredApprovals: 1, ApproverRoleID: pgtype.UUID{Bytes: rUUID, Valid: true},
		Name: pgtype.Text{String: "p2", Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateRequestPolicy p2: %v", err)
	}

	// An active grant of R to the subject on the asset, with a future expiry, plus a
	// live session it (and the standing binding) authorize.
	greq, err := q.CreateAccessRequest(ctx, gen.CreateAccessRequestParams{
		RequesterUserID: f.user, RoleID: rUUID, AssetID: f.asset,
		Reason: "seed", RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		RequiredApprovals: 0, GrantedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true}, Status: "granted",
	})
	if err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	grant, err := q.CreateAccessGrant(ctx, gen.CreateAccessGrantParams{
		RequestID: greq.ID, RoleID: rUUID, ScopeAssetID: f.asset, SubjectUserID: f.user,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	sess := f.seedSession(t)

	// Baseline: the session is authorized (the binding stands) — a sweep leaves it.
	f.sweep(t)
	if f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("authorized session: terminate_requested_at must be NULL before delete")
	}

	// Delete R via the public API.
	if _, err := f.acc.DeleteRole(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleRequest{
		RoleId: roleID,
	}), f.admin)); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	// The role row is gone.
	if _, err := q.GetRole(ctx, rUUID); err == nil {
		t.Fatal("role still present after DeleteRole")
	}

	// No bindings of R remain.
	if bs, err := q.ListRoleBindings(ctx, gen.ListRoleBindingsParams{RoleID: pgtype.UUID{Bytes: rUUID, Valid: true}, Lim: 100}); err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	} else if len(bs) != 0 {
		t.Fatalf("role bindings after delete = %d, want 0", len(bs))
	}

	// No role-grant edges touching R remain in EITHER direction.
	var edgeCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM role_grants WHERE role_id = $1 OR source_role_id = $1`, rUUID).Scan(&edgeCount); err != nil {
		t.Fatalf("count role_grants: %v", err)
	}
	if edgeCount != 0 {
		t.Fatalf("role_grants touching R after delete = %d, want 0", edgeCount)
	}

	// P1 (and its subjects) are gone.
	if _, err := q.GetRequestPolicy(ctx, p1.ID); err == nil {
		t.Fatal("policy p1 still present after DeleteRole")
	}
	var subjCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM request_policy_subjects WHERE policy_id = $1`, p1.ID).Scan(&subjCount); err != nil {
		t.Fatalf("count p1 subjects: %v", err)
	}
	if subjCount != 0 {
		t.Fatalf("p1 subjects after delete = %d, want 0", subjCount)
	}

	// P2 SURVIVES, with approver_role_id NULLed (its requestable role O is intact).
	p2after, err := q.GetRequestPolicy(ctx, p2.ID)
	if err != nil {
		t.Fatalf("policy p2 must survive: %v", err)
	}
	if p2after.ApproverRoleID.Valid {
		t.Fatalf("p2 approver_role_id must be NULL after delete, got %v", p2after.ApproverRoleID)
	}
	if p2after.RoleID != other.ID {
		t.Fatalf("p2 requestable role changed: got %v want %v", p2after.RoleID, other.ID)
	}

	// The grant was revoked: its row is FK-cascaded away by the role delete, so the
	// observable proof is the audit trail — a grant-revoked event for it — and the
	// live-session teardown below.
	if _, err := q.GetGrant(ctx, grant.ID); err != pgx.ErrNoRows {
		t.Fatalf("grant row should be gone (cascaded), got err=%v", err)
	}

	// The sweep (fired by the binding/edge deletes) tears down the now-unauthorized
	// session: R is gone, so the subject holds no login on the asset.
	f.sweep(t)
	if !f.terminateRequestedAt(t, sess).Valid {
		t.Fatal("deauthorized session: terminate_requested_at must be set after DeleteRole + sweep")
	}

	// Audit: exactly one grant-revoked event for this grant, and a session-terminated
	// event; the hash chain stays intact.
	if n := grantRevokedCount(t, f, grant.ID); n != 1 {
		t.Fatalf("access_grant.revoked events for grant = %d, want 1", n)
	}
	if n := f.sessionTerminatedCount(t); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(f.pool).Verify(ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}

	// A random (non-existent) role id is NotFound.
	_, err = f.acc.DeleteRole(ctx, withToken(connect.NewRequest(&accessv1.DeleteRoleRequest{
		RoleId: uuid.NewString(),
	}), f.admin))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("DeleteRole(random) code = %v, want NotFound", got)
	}
}

// grantRevokedCount drains the audit outbox and counts access_grant.revoked entries
// whose details name the given grant id.
func grantRevokedCount(t *testing.T, f *cascadeFixture, grantID uuid.UUID) int {
	t.Helper()
	for {
		n, err := audit.New(f.pool).DrainOnce(f.ctx, 256)
		if err != nil {
			t.Fatalf("DrainOnce: %v", err)
		}
		if n < 256 {
			break
		}
	}
	rows, err := f.q.ListAuditEntries(f.ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	want := "access_grant:" + grantID.String()
	n := 0
	for _, r := range rows {
		if r.EventType == accessrequest.EventGrantRevoked && r.Subject == want {
			n++
		}
	}
	return n
}
