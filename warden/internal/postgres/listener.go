package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Listen issues a LISTEN on channel over conn. LISTEN cannot be parameterized, so
// the channel name is interpolated after being sanitized as a pgx identifier —
// keeping this the one place raw channel SQL is constructed (there is no sqlc form
// for LISTEN + WaitForNotification). The NOTIFY side uses the sqlc NotifyChannel
// query (pg_notify accepts bind parameters).
func Listen(ctx context.Context, conn *pgx.Conn, channel string) error {
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return fmt.Errorf("listen %q: %w", channel, err)
	}
	return nil
}

// WaitNotification blocks until a notification arrives on a channel conn is
// LISTENing to, or ctx is cancelled (returning ctx's error). It is a thin pass to
// pgx.Conn.WaitForNotification so callers reach it through the postgres boundary.
func WaitNotification(ctx context.Context, conn *pgx.Conn) (*pgconn.Notification, error) {
	return conn.WaitForNotification(ctx)
}
