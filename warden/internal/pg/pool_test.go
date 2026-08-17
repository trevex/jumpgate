package pg_test

import (
	"context"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/pg"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func TestNewPoolConnects(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	pool, err := pg.NewPool(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	var one int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query: %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 = %d", one)
	}
}

func TestNewPoolBadDSN(t *testing.T) {
	if _, err := pg.NewPool(context.Background(), "not-a-valid-dsn://"); err == nil {
		t.Fatal("expected error for invalid dsn")
	}
}
