//go:build bench

package bench

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/rpc"
)

func benchCtx(w *World) context.Context {
	return auth.WithUser(context.Background(), auth.CurrentUser{ID: w.DeepSubject, Email: "u0@bench.test"})
}

func benchAccessService(b *testing.B) *accessrequest.Service {
	pool, _ := sharedDB(b)
	return accessrequest.NewService(
		pool, audit.New(pool), approvals.New(pool),
		authz.NewRoleResolver(pool), accessrequest.NoopTerminator{}, time.Hour,
	)
}

func benchCatalog(b *testing.B) *rpc.CatalogServer {
	pool, _ := sharedDB(b)
	q := sqlc.New(pool)
	a := authz.New(pool)
	return rpc.NewCatalogServer(q, pool, a, benchAccessService(b), nil, nil)
}

// BenchmarkBrowseFolder benches the catalog browse-landing path (root contents,
// visibility-filtered) — the operation whose N+1 originally motivated the suite.
func BenchmarkBrowseFolder(b *testing.B) {
	srv := benchCatalog(b)
	runAcross(b, func(b *testing.B, w *World) {
		ctx := benchCtx(w)
		req := connect.NewRequest(&catalogv1.ListFolderContentsRequest{Parent: ""})
		for i := 0; i < b.N; i++ {
			if _, err := srv.ListFolderContents(ctx, req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGetAssetAccess(b *testing.B) {
	srv := benchCatalog(b)
	runAcross(b, func(b *testing.B, w *World) {
		ctx := benchCtx(w)
		req := connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: w.LeafAsset.String()})
		for i := 0; i < b.N; i++ {
			if _, err := srv.GetAssetAccess(ctx, req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSearchCatalog(b *testing.B) {
	srv := benchCatalog(b)
	runAcross(b, func(b *testing.B, w *World) {
		ctx := benchCtx(w)
		req := connect.NewRequest(&catalogv1.SearchCatalogRequest{Query: "leaf", Limit: 20})
		for i := 0; i < b.N; i++ {
			if _, err := srv.SearchCatalog(ctx, req); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkListPendingApprovals is the N+1 sentinel: its queries/op reflects the
// approver-resolution work per pending request.
func BenchmarkListPendingApprovals(b *testing.B) {
	svc := benchAccessService(b)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := svc.ListPendingApprovals(ctx, w.Approver); err != nil {
				b.Fatal(err)
			}
		}
	})
}
