//go:build bench

package bench

import (
	"context"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

func benchAuthz(b *testing.B) authz.Authorizer {
	pool, _ := sharedDB(b)
	return authz.NewSQLAuthorizer(pool)
}

func BenchmarkCheck(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.Check(ctx, w.DeepSubject, w.LeafAsset, "ssh:connect"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCapabilitiesOnAsset(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.CapabilitiesOnAsset(ctx, w.DeepSubject, w.LeafAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCapabilitiesOnScope(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.CapabilitiesOnScope(ctx, w.DeepSubject, authz.GlobalScope()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVisibleFoldersUnder(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.VisibleFoldersUnder(ctx, w.DeepSubject, w.RootParent, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVisibleAssetsUnder(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.VisibleAssetsUnder(ctx, w.DeepSubject, w.MidFolder, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVisibleRolesUnder(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.VisibleRolesUnder(ctx, w.DeepSubject, w.RootParent, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVisibleGroupsUnder(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := a.VisibleGroupsUnder(ctx, w.DeepSubject, w.RootParent, true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkEntitledLogins(b *testing.B) {
	a := benchAuthz(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := authz.EntitledLogins(ctx, a, w.DeepSubject, w.LeafAsset, w.LeafLogins); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHoldsRole(b *testing.B) {
	pool, _ := sharedDB(b)
	rr := authz.NewRoleResolver(pool)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := rr.HoldsRole(ctx, w.DeepSubject, w.RequestRole, "asset", w.LeafAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHoldsRoleStanding(b *testing.B) {
	pool, _ := sharedDB(b)
	rr := authz.NewRoleResolver(pool)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := rr.HoldsRoleStanding(ctx, w.DeepSubject, w.RequestRole, "asset", w.LeafAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkIsApprover(b *testing.B) {
	pool, _ := sharedDB(b)
	r := approvals.New(pool)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := r.IsApprover(ctx, w.Approver, w.RequestRole, w.RequestAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkIsEligibleRequester(b *testing.B) {
	pool, _ := sharedDB(b)
	r := approvals.New(pool)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := r.IsEligibleRequester(ctx, w.DeepSubject, w.RequestRole, w.RequestAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}
