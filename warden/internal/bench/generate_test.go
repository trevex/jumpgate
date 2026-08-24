//go:build bench

package bench

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// tinyProfile is a fast profile for generator unit tests (not a bench profile).
var tinyProfile = Profile{
	Name: "tiny", FolderFanout: 2, FolderDepth: 2,
	GroupChainDepth: 2, GroupsPerFolder: 1, UsersPerLeafGrp: 1,
	RolesPerFolder: 1, RoleGrantDepth: 2, RoleGrantVia: "parent",
	BindingsPerFolder: 1, PoliciesPerFolder: 1, LiveSessions: 2,
	Users: 5, CapsPerRole: 2,
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
