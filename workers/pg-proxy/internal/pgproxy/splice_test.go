package pgproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/trevex/jumpgate/workers/pg-proxy/internal/record"
)

// rec == nil path preserves the pre-recording dual byte-copy behavior.
func TestSpliceEchoes(t *testing.T) {
	clientLocal, clientRemote := net.Pipe()
	targetLocal, targetRemote := net.Pipe()

	cancel := make(chan struct{})
	go Splice(nil, clientRemote, targetRemote, cancel, nil, time.Time{})

	go func() {
		buf := make([]byte, 64)
		n, err := targetLocal.Read(buf)
		if err != nil {
			return
		}
		_, _ = targetLocal.Write(buf[:n])
	}()

	_ = clientLocal.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientLocal.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(clientLocal, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("got %q, want %q", got, "ping")
	}
}

func TestSpliceCancelCloses(t *testing.T) {
	clientLocal, clientRemote := net.Pipe()
	_, targetRemote := net.Pipe()

	cancel := make(chan struct{})
	go Splice(nil, clientRemote, targetRemote, cancel, nil, time.Time{})
	close(cancel)

	_ = clientLocal.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := clientLocal.Read(buf); err == nil {
		t.Fatal("expected read error after cancel closed the conn, got nil")
	}
}

func TestFrontendEventRedactsParams(t *testing.T) {
	start := time.Now().Add(-10 * time.Millisecond)

	ev, ok := frontendEvent(&pgproto3.Bind{
		PreparedStatement: "s1", DestinationPortal: "",
		Parameters: [][]byte{[]byte("123-45-6789"), []byte("secret")},
	}, start)
	if !ok {
		t.Fatal("bind not mapped")
	}
	if ev["params"] != 2 {
		t.Errorf("params = %v, want 2", ev["params"])
	}
	blob, _ := json.Marshal(ev)
	if strings.Contains(string(blob), "123-45-6789") || strings.Contains(string(blob), "secret") {
		t.Errorf("bind event leaked param values: %s", blob)
	}

	q, ok := frontendEvent(&pgproto3.Query{String: "SELECT 1"}, start)
	if !ok || q["sql"] != "SELECT 1" || q["type"] != "query" {
		t.Errorf("query event = %v", q)
	}

	p, ok := frontendEvent(&pgproto3.Parse{Name: "s1", Query: "SELECT $1", ParameterOIDs: []uint32{25}}, start)
	if !ok || p["sql"] != "SELECT $1" {
		t.Errorf("parse event = %v", p)
	}
}

func TestBackendEventOutcomes(t *testing.T) {
	start := time.Now()
	cc, ok := backendEvent(&pgproto3.CommandComplete{CommandTag: []byte("DELETE 4000")}, start)
	if !ok || cc["tag"] != "DELETE 4000" {
		t.Errorf("command_complete = %v", cc)
	}
	er, ok := backendEvent(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "no relation"}, start)
	if !ok || er["code"] != "42P01" || er["type"] != "error" {
		t.Errorf("error = %v", er)
	}
	if _, ok := backendEvent(&pgproto3.DataRow{}, start); ok {
		t.Error("DataRow must NOT be recorded (that is the database's data)")
	}
}

type memUp struct{ body []byte }

func (m *memUp) Put(_ context.Context, _ string, body []byte) error {
	m.body = append([]byte(nil), body...)
	return nil
}

// pumpClient records a forwarded Query and delivers the exact bytes to the target.
func TestPumpClientForwardsAndRecords(t *testing.T) {
	clientR, clientW := net.Pipe()
	targetR, targetW := net.Pipe()

	up := &memUp{}
	rec := record.New(up, "k", record.Header{V: 1, Kind: "pg"})
	be := pgproto3.NewBackend(clientR, clientR)

	go func() {
		fe := pgproto3.NewFrontend(clientW, clientW)
		fe.Send(&pgproto3.Query{String: "SELECT 1"})
		_ = fe.Flush()
		time.Sleep(50 * time.Millisecond)
		_ = clientW.Close()
	}()

	got := make(chan string, 1)
	go func() {
		tbe := pgproto3.NewBackend(targetR, targetR)
		for {
			msg, err := tbe.Receive()
			if err != nil {
				return
			}
			if q, ok := msg.(*pgproto3.Query); ok {
				got <- q.String
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- pumpClient(be, targetW, rec, time.Now()) }()

	select {
	case s := <-got:
		if s != "SELECT 1" {
			t.Fatalf("forwarded query = %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for forwarded query")
	}
	_ = targetW.Close()
	if err := <-done; err != nil {
		t.Errorf("clean client disconnect must not fail closed, got %v", err)
	}

	_ = rec.Finish(context.Background(), 0)
	if !strings.Contains(string(up.body), `"sql":"SELECT 1"`) {
		t.Errorf("recorder missing query: %s", up.body)
	}
}

// A frontend parse error must terminate pumpClient with a non-nil error (fail closed).
func TestPumpClientFailClosedOnParseError(t *testing.T) {
	clientR, clientW := net.Pipe()
	_, targetW := net.Pipe()
	up := &memUp{}
	rec := record.New(up, "k", record.Header{V: 1, Kind: "pg"})
	be := pgproto3.NewBackend(clientR, clientR)

	go func() {
		_, _ = clientW.Write([]byte{0xFF, 0x00, 0x00, 0x00, 0x04})
		_ = clientW.Close()
	}()

	if err := pumpClient(be, targetW, rec, time.Now()); err == nil {
		t.Fatal("pumpClient on garbage: err = nil, want fail-closed error")
	}
}
