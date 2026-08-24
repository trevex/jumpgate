//go:build bench

package bench

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedRequesters creates n distinct eligible requester users (fresh members of the
// world's requester group; they hold no role, so they are eligible AND not
// already-active). Used untimed by runWriteBench for BenchmarkRequestAccess.
func seedRequesters(b *testing.B, w *World, n int) []uuid.UUID {
	pool, _ := sharedDB(b)
	ctx := context.Background()
	out := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		u := insertUser(ctx, b, pool, fmt.Sprintf("wreq-%d@bench.test", i))
		addUserToGroup(ctx, b, pool, w.RequesterGroup, u)
		out[i] = u
	}
	return out
}

// seedPendingForApproval creates n distinct pending requests, each from a distinct
// fresh requester (≠ the approver, so no self-approve; distinct so each satisfies
// uq_pending_request). Used untimed by runWriteBench for BenchmarkApproveRequest.
func seedPendingForApproval(b *testing.B, w *World, n int) []uuid.UUID {
	pool, _ := sharedDB(b)
	ctx := context.Background()
	out := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		u := insertUser(ctx, b, pool, fmt.Sprintf("wapp-%d@bench.test", i))
		addUserToGroup(ctx, b, pool, w.RequesterGroup, u)
		out[i] = insertOpenRequest(ctx, b, pool, u, w.RequestRole, w.RequestAsset)
	}
	return out
}

// BenchmarkRequestAccess benches the request-creation path (eligibility resolution +
// already-active check + insert), one distinct eligible requester per iteration.
func BenchmarkRequestAccess(b *testing.B) {
	svc := benchAccessService(b)
	runWriteBench(b, seedRequesters, func(ctx context.Context, w *World, requester uuid.UUID) error {
		_, err := svc.RequestAccess(ctx, requester, w.RequestRole, w.RequestAsset, time.Hour, "bench")
		return err
	})
}

// BenchmarkApproveRequest benches the approval path (approver resolution + grant
// mint + status transition), one distinct pending request per iteration.
func BenchmarkApproveRequest(b *testing.B) {
	svc := benchAccessService(b)
	runWriteBench(b, seedPendingForApproval, func(ctx context.Context, w *World, requestID uuid.UUID) error {
		_, err := svc.Approve(ctx, w.Approver, requestID)
		return err
	})
}
