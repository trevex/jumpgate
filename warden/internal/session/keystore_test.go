package session_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	s, err := secrets.NewSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyStoreInitAndLoad(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	ks := session.NewKeyStore(gen.New(pool), testSealer(t))

	if _, _, err := ks.LoadActive(ctx); err == nil {
		t.Fatal("LoadActive must fail before Init")
	}
	if err := ks.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := ks.Init(ctx); err == nil {
		t.Fatal("second Init must fail (already active)")
	}
	priv, pub, err := ks.LoadActive(ctx)
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if len(pub) != 32 || len(priv) != 64 {
		t.Fatalf("unexpected key sizes: priv=%d pub=%d", len(priv), len(pub))
	}
}
