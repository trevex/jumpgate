package testsupport

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStartPostgresProcess(t *testing.T) {
	dsn, stop, err := StartPostgresProcess()
	if err != nil {
		t.Skipf("postgres tooling unavailable: %v", err)
	}
	defer stop()

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
