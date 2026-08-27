//go:build bench

package bench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// BenchmarkCreateSession benches the per-connect admission path (entitlement
// closure + token mint). It is read-only (mints a token, no DB write).
func BenchmarkCreateSession(b *testing.B) {
	pool, _ := sharedDB(b)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	svc := session.NewService(sqlc.New(pool), authz.New(pool),
		sessiontoken.NewMinter(priv), "gw.bench:8443", time.Minute)
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if _, err := svc.CreateSession(ctx, w.DeepSubject, w.LeafAsset, "SHA256:benchfp"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkReevaluate benches the per-(user,asset) teardown decision — the atom of
// continuous revocation. The deep subject retains access, so no teardown occurs.
func BenchmarkReevaluate(b *testing.B) {
	pool, _ := sharedDB(b)
	term := dataplane.NewTerminator(pool, authz.New(pool), audit.New(pool))
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		for i := 0; i < b.N; i++ {
			if err := term.Reevaluate(ctx, w.DeepSubject, w.LeafAsset); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSweepOwned benches the revocation fan-out: it re-evaluates the connect
// predicate for the live (user,asset) pairs on the connected workers.
func BenchmarkSweepOwned(b *testing.B) {
	pool, _ := sharedDB(b)
	term := dataplane.NewTerminator(pool, authz.New(pool), audit.New(pool))
	ctx := context.Background()
	runAcross(b, func(b *testing.B, w *World) {
		reg := dataplane.NewRegistry()
		for _, wk := range w.Workers {
			reg.Add(wk, make(chan dataplane.Signal, 1))
		}
		sweeper := dataplane.NewSweeper(pool, reg, term)
		for i := 0; i < b.N; i++ {
			if err := sweeper.SweepOwned(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
