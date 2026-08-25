// Package postgres provides the control-plane's PostgreSQL infrastructure.
package postgres

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"
)

// NewPool creates and verifies a pgx connection pool for dsn.
// It registers the google/uuid codec so that uuid.UUID values can be scanned
// from UUID columns returned by raw pool queries.
func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 25
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		// Disable JIT for this connection. Warden is an OLTP control-plane: every
		// query runs over small data, so LLVM JIT compilation is pure overhead that
		// never pays off. Worse, the authz hot paths are recursive-CTE closures whose
		// row counts Postgres grossly over-estimates (a tiny held/requestable closure
		// is costed in the tens of millions), tripping jit_above_cost and triggering a
		// full inline+optimize compile (~500ms of code generation) on every browse —
		// dwarfing the ~6ms of actual execution. Turning JIT off keeps these queries at
		// their real cost. Set on the connection so it holds regardless of the server's
		// jit setting (warden may run against a managed Postgres we don't configure).
		if _, err := conn.Exec(ctx, "SET jit = off"); err != nil {
			return fmt.Errorf("disable jit: %w", err)
		}
		return nil
	}
	// Bound dead-peer detection for long-lived LISTEN connections: a session that
	// blocks in WaitForNotification holds an idle socket, so a silently-dropped path
	// (NAT/LB timeout, peer crash) would otherwise go unnoticed for the OS default
	// (~11 min) or never. TCP keepalive probes force detection in ~1 minute.
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     30 * time.Second,
			Interval: 10 * time.Second,
			Count:    3,
		},
	}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}
