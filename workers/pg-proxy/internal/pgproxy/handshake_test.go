package pgproxy_test

import (
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/trevex/jumpgate/workers/pg-proxy/internal/pgproxy"
)

// hs holds the state left after a completed client-side startup handshake.
type hs struct {
	be      *pgproto3.Backend
	fe      *pgproto3.Frontend
	startup pgproxy.Startup
}

// doHandshake drives a fake psql client (pgproto3.Frontend) through the SSL
// decline + StartupMessage exchange against pgproxy.ReadStartup on the other end
// of a net.Pipe, and returns the server Backend + client Frontend for the caller
// to exercise CompleteAuth/RejectUser.
func doHandshake(t *testing.T) hs {
	t.Helper()
	client, server := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	fe := pgproto3.NewFrontend(client, client)

	type res struct {
		be  *pgproto3.Backend
		s   pgproxy.Startup
		err error
	}
	ch := make(chan res, 1)
	go func() {
		be, s, err := pgproxy.ReadStartup(server)
		ch <- res{be, s, err}
	}()

	// SSL negotiation: client asks, server must decline with a single 'N'.
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("read ssl reply: %v", err)
	}
	if buf[0] != 'N' {
		t.Fatalf("ssl reply = %q, want 'N'", buf[0])
	}

	// Real startup.
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "app", "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send StartupMessage: %v", err)
	}

	r := <-ch
	if r.err != nil {
		t.Fatalf("ReadStartup: %v", r.err)
	}
	if r.be == nil {
		t.Fatal("ReadStartup returned nil Backend")
	}
	return hs{be: r.be, fe: fe, startup: r.s}
}

func TestReadStartupDeclinesSSLAndParses(t *testing.T) {
	h := doHandshake(t)
	if h.startup.User != "app" {
		t.Errorf("User = %q, want %q", h.startup.User, "app")
	}
	if h.startup.Database != "appdb" {
		t.Errorf("Database = %q, want %q", h.startup.Database, "appdb")
	}
}

func TestCompleteAuth(t *testing.T) {
	h := doHandshake(t)

	errc := make(chan error, 1)
	go func() { errc <- pgproxy.CompleteAuth(h.be) }()

	m1, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive 1: %v", err)
	}
	if _, ok := m1.(*pgproto3.AuthenticationOk); !ok {
		t.Fatalf("message 1 = %T, want *pgproto3.AuthenticationOk", m1)
	}
	m2, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive 2: %v", err)
	}
	if _, ok := m2.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("message 2 = %T, want *pgproto3.ReadyForQuery", m2)
	}
	if err := <-errc; err != nil {
		t.Fatalf("CompleteAuth: %v", err)
	}
}

func TestRejectUser(t *testing.T) {
	h := doHandshake(t)

	go pgproxy.RejectUser(h.be, "role not permitted")

	m, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	e, ok := m.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("message = %T, want *pgproto3.ErrorResponse", m)
	}
	if e.Severity != "FATAL" {
		t.Errorf("Severity = %q, want %q", e.Severity, "FATAL")
	}
}
