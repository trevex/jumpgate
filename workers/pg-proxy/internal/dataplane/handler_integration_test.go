package dataplane

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/control"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakeDataplaneClient stands in for warden: SetupSession returns a canned
// response pointing at the ephemeral Postgres with a pg-password credential.
type fakeDataplaneClient struct {
	addr, db string
}

func (f fakeDataplaneClient) SetupSession(_ context.Context, _ *connect.Request[dataplanev1.SetupSessionRequest]) (*connect.Response[dataplanev1.SetupSessionResponse], error) {
	return connect.NewResponse(&dataplanev1.SetupSessionResponse{
		TargetAddress:   f.addr,
		DefaultDatabase: f.db,
		Login:           "app",
		SessionId:       "sess-1",
		Credential:      &dataplanev1.SetupSessionResponse_PgPassword{PgPassword: "s3cr3t"},
	}), nil
}

func (f fakeDataplaneClient) WorkerStream(context.Context) *connect.BidiStreamForClient[dataplanev1.WorkerMessage, dataplanev1.ServerMessage] {
	panic("unused")
}

var _ dataplanev1connect.DataplaneServiceClient = fakeDataplaneClient{}

// TestHandleConnProxiesToPostgres drives handleConn end-to-end over a net.Pipe:
// CONNECT preamble -> pgwire startup -> (faked) SetupSession redeem -> real dial
// to an ephemeral Postgres -> splice, and asserts SELECT 1 returns a row through
// the proxy. A deadline on the client side means any hang fails the test.
func TestHandleConnProxiesToPostgres(t *testing.T) {
	addr, db, stop := startPostgres(t)
	defer stop()

	cliConn, srvConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleConn(ctx, srvConn, "pg-0", fakeDataplaneClient{addr: addr, db: db},
		control.NewRegistry(), make(chan control.SessionEnd, 1))
	defer func() { _ = cliConn.Close() }()

	if err := cliConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// One bufio.Reader over cliConn for both the CONNECT response and pgwire, so
	// bytes the reader buffers past the header terminator aren't lost.
	br := bufio.NewReader(cliConn)

	if _, err := io.WriteString(cliConn, "CONNECT asset HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT not established: %q", strings.TrimSpace(status))
	}
	for { // drain headers up to the blank line
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	fe := pgproto3.NewFrontend(br, cliConn)

	// Decline SSL (tunnel is already the mesh; the proxy replies with a single 'N').
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush SSLRequest: %v", err)
	}
	if b, err := br.ReadByte(); err != nil || b != 'N' {
		t.Fatalf("expected 'N' SSL decline, got %q err=%v", b, err)
	}

	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "app", "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}

	// AuthenticationOk then ReadyForQuery (auth is trivial on the client hop).
	waitFor[*pgproto3.ReadyForQuery](t, fe)

	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush query: %v", err)
	}

	// RowDescription, then the DataRow carrying "1", then CommandComplete + ReadyForQuery.
	waitFor[*pgproto3.RowDescription](t, fe)
	row := waitFor[*pgproto3.DataRow](t, fe)
	if len(row.Values) != 1 || string(row.Values[0]) != "1" {
		t.Fatalf("SELECT 1 returned %q, want single column \"1\"", row.Values)
	}
	waitFor[*pgproto3.CommandComplete](t, fe)
	waitFor[*pgproto3.ReadyForQuery](t, fe)
}

// waitFor receives backend messages until one of type T arrives (skipping the
// expected intervening messages), failing on any receive error (deadline hang).
func waitFor[T pgproto3.BackendMessage](t *testing.T, fe *pgproto3.Frontend) T {
	t.Helper()
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive waiting for %T: %v", *new(T), err)
		}
		if got, ok := msg.(T); ok {
			return got
		}
	}
}
