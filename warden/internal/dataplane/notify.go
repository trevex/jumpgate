package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

const teardownChannel = "session_teardown"

type teardownPayload struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// NotifyTeardown publishes a teardown intent for sessionID on the teardown
// channel. Any replica LISTENing will deliver it if it owns that worker's stream.
func NotifyTeardown(ctx context.Context, pool *pgxpool.Pool, sessionID, reason string) error {
	p, _ := json.Marshal(teardownPayload{SessionID: sessionID, Reason: reason})
	if _, err := pool.Exec(ctx, "SELECT pg_notify($1, $2)", teardownChannel, string(p)); err != nil {
		return fmt.Errorf("notify teardown: %w", err)
	}
	return nil
}

// Listener subscribes to the teardown channel and pushes signals to locally-owned
// worker streams via the registry.
type Listener struct {
	pool *pgxpool.Pool
	reg  *Registry
}

// NewListener builds a teardown Listener.
func NewListener(pool *pgxpool.Pool, reg *Registry) *Listener { return &Listener{pool: pool, reg: reg} }

// Run holds a dedicated connection, LISTENs on the teardown channel, and dispatches
// notifications until ctx is cancelled. On connection loss it backs off and
// re-establishes the LISTEN (a missed notification self-heals via reconnect/pull
// reconciliation). Returns ctx.Err() when cancelled.
func (l *Listener) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if err := l.listenLoop(ctx); err != nil && ctx.Err() == nil {
			slog.Error("teardown listener error; retrying", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
	return ctx.Err()
}

func (l *Listener) listenLoop(ctx context.Context) error {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+teardownChannel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var p teardownPayload
		if err := json.Unmarshal([]byte(n.Payload), &p); err != nil {
			slog.Error("bad teardown payload", "payload", n.Payload, "err", err)
			continue
		}
		l.dispatch(ctx, p)
	}
}

// dispatch looks up the session's owning worker and pushes the teardown if this
// replica holds that stream. If the session is gone or not owned here, it's a
// no-op (another replica delivers, or reconnect/pull reconciles).
func (l *Listener) dispatch(ctx context.Context, p teardownPayload) {
	sid, err := uuid.Parse(p.SessionID)
	if err != nil {
		return
	}
	row, err := sqlc.New(l.pool).GetLiveSession(ctx, sid)
	if err != nil {
		return
	}
	l.reg.Push(row.WorkerID, Signal(p))
}
