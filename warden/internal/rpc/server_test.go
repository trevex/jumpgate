package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// testAccessRequestService builds a shared access-request Service for the rpc test
// servers (mirrors the wiring in main.go / rpc.Register).
func testAccessRequestService(pool *pgxpool.Pool) *accessrequest.Service {
	return accessrequest.NewService(
		pool,
		audit.New(pool),
		approvals.New(pool),
		authz.NewRoleResolver(pool),
		accessrequest.NoopTerminator{},
		8*time.Hour,
	)
}

func TestMuxServesHealthzAndRegisters(t *testing.T) {
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	mux := http.NewServeMux()
	mux.Handle("/", httpapi.NewRouter(pool))
	if err := rpc.Register(mux, pool, testAccessRequestService(pool)); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}
