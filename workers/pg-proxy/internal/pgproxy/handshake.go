// Package pgproxy implements the pg-proxy worker's PostgreSQL data path: the
// client-facing pgwire handshake, the credential-injected target dial, and the
// byte splice between them.
package pgproxy

import (
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Startup is the parsed client StartupMessage parameters we care about.
type Startup struct {
	User     string
	Database string
}

// ReadStartup completes the pgwire startup phase on the client side: it declines
// SSL/GSS (single 'N' byte — the tunnel is already encrypted) and returns the
// client's StartupMessage parameters. The Backend is returned for the caller to
// complete or reject auth once authorization is known.
func ReadStartup(conn net.Conn) (*pgproto3.Backend, Startup, error) {
	be := pgproto3.NewBackend(conn, conn)
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return nil, Startup{}, fmt.Errorf("receive startup: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte("N")); err != nil {
				return nil, Startup{}, fmt.Errorf("decline ssl: %w", err)
			}
		case *pgproto3.StartupMessage:
			return be, Startup{User: m.Parameters["user"], Database: m.Parameters["database"]}, nil
		case *pgproto3.CancelRequest:
			return nil, Startup{}, io.EOF // MVP: ignore cancels; caller closes
		default:
			return nil, Startup{}, fmt.Errorf("unexpected startup message %T", m)
		}
	}
}

// CompleteAuth tells the client its startup succeeded (trivial auth — the tunnel
// is already authenticated) and that the server is ready for queries.
func CompleteAuth(be *pgproto3.Backend) error {
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return be.Flush()
}

// RejectUser sends a FATAL error and flushes (caller then closes).
func RejectUser(be *pgproto3.Backend, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: msg})
	_ = be.Flush()
}
