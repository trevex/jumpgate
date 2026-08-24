//go:build bench

package bench

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// tinyProfile is a fast profile for generator unit tests (not a bench profile).
var tinyProfile = Profile{
	Name: "tiny", FolderFanout: 2, FolderDepth: 2,
	GroupChainDepth: 2, GroupsPerFolder: 1, UsersPerLeafGrp: 1,
	RolesPerFolder: 1, RoleGrantDepth: 2, RoleGrantVia: "parent",
	BindingsPerFolder: 1, PoliciesPerFolder: 1, LiveSessions: 2,
	PendingRequests: 3, Users: 5, CapsPerRole: 2,
}

func TestGenerateProducesReachableDeepSubject(t *testing.T) {
	pool, _ := sharedDB(t)
	w := Generate(t, tinyProfile)

	var folders int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM folders").Scan(&folders); err != nil {
		t.Fatalf("count folders: %v", err)
	}
	if folders == 0 {
		t.Fatal("no folders generated")
	}
	if w.DeepSubject.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("deep subject not set")
	}
	if w.LeafAsset.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("leaf asset not set")
	}
	if len(w.LeafLogins) == 0 {
		t.Fatal("leaf asset has no configured logins")
	}
}

func TestGenerateDeepSubjectHoldsRoleViaClosure(t *testing.T) {
	pool, _ := sharedDB(t)
	w := Generate(t, tinyProfile)
	a := authz.NewSQLAuthorizer(pool)
	ok, err := a.Check(context.Background(), w.DeepSubject, w.LeafAsset, "ssh:connect")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !ok {
		t.Fatal("deep subject cannot ssh:connect to leaf asset — closure fixture is empty")
	}
	if w.PendingReq == uuid.Nil {
		t.Fatal("no pending request generated for approval benches")
	}
	if w.Approver == uuid.Nil {
		t.Fatal("no approver generated")
	}
}

func TestGenerateRequesterFixtures(t *testing.T) {
	pool, _ := sharedDB(t)
	w := Generate(t, tinyProfile)
	if w.RequesterGroup == uuid.Nil {
		t.Fatal("requester group not set")
	}
	if len(w.PendingReqs) != tinyProfile.PendingRequests {
		t.Fatalf("PendingReqs = %d, want %d", len(w.PendingReqs), tinyProfile.PendingRequests)
	}
	var pending int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM access_requests WHERE status = 'pending'").Scan(&pending); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != tinyProfile.PendingRequests {
		t.Fatalf("pending access_requests = %d, want %d", pending, tinyProfile.PendingRequests)
	}
	// A freshly-added member of the requester group must be an eligible requester
	// (the whole point of the fixture) and must NOT already hold the role.
	ctx := context.Background()
	ru := insertUser(ctx, t, pool, "eligibility-probe@bench.test")
	addUserToGroup(ctx, t, pool, w.RequesterGroup, ru)
	r := approvals.New(pool)
	eligible, err := r.IsEligibleRequester(ctx, ru, w.RequestRole, w.RequestAsset)
	if err != nil {
		t.Fatalf("IsEligibleRequester: %v", err)
	}
	if !eligible {
		t.Fatal("requester-group member is not an eligible requester")
	}
}

func TestGenerateLiveSessions(t *testing.T) {
	pool, _ := sharedDB(t)
	w := Generate(t, tinyProfile)
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM live_sessions").Scan(&n); err != nil {
		t.Fatalf("count live_sessions: %v", err)
	}
	if n != tinyProfile.LiveSessions {
		t.Fatalf("live_sessions = %d, want %d", n, tinyProfile.LiveSessions)
	}
	if len(w.LivePairs) != tinyProfile.LiveSessions || len(w.Workers) == 0 {
		t.Fatalf("world live fixtures: pairs=%d workers=%d", len(w.LivePairs), len(w.Workers))
	}
}
