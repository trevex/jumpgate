package dataplane

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/control"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakeDataplaneClient stands in for warden's two-phase flow: PrepareSession
// returns the ephemeral Postgres endpoint plus a tls_leaf anchor pinned to the
// target's self-signed cert (so the worker's credential-free observe matches it),
// and IssueSessionCredential releases the pg-password credential — but only after
// the worker reports a matched anchor + observed fingerprint. issued records the
// last IssueSessionCredential request so a test can assert issuance order/inputs.
type fakeDataplaneClient struct {
	addr, db, leafFP string
	issued           *dataplanev1.IssueSessionCredentialRequest
}

func (f *fakeDataplaneClient) PrepareSession(_ context.Context, _ *connect.Request[dataplanev1.PrepareSessionRequest]) (*connect.Response[dataplanev1.PrepareSessionResponse], error) {
	return connect.NewResponse(&dataplanev1.PrepareSessionResponse{
		TargetAddress:    f.addr,
		DefaultDatabase:  f.db,
		Login:            "app",
		SessionId:        "sess-1",
		EndpointRevision: 1,
		TrustAnchors: []*dataplanev1.SessionTrustAnchor{{
			Id:                "anchor-1",
			Kind:              "tls_leaf",
			Algorithm:         "x509",
			Sha256Fingerprint: f.leafFP,
		}},
	}), nil
}

func (f *fakeDataplaneClient) IssueSessionCredential(_ context.Context, req *connect.Request[dataplanev1.IssueSessionCredentialRequest]) (*connect.Response[dataplanev1.IssueSessionCredentialResponse], error) {
	f.issued = req.Msg
	// Stand-in for warden's enforcement: a real caller only reaches here with a
	// matched anchor; refuse if the worker somehow issued without one.
	if req.Msg.GetMatchedAnchorId() == "" || req.Msg.GetObservedFingerprint() == "" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("no matched anchor"))
	}
	return connect.NewResponse(&dataplanev1.IssueSessionCredentialResponse{
		SessionId:  req.Msg.GetSessionId(),
		Login:      "app",
		Credential: &dataplanev1.IssueSessionCredentialResponse_PgPassword{PgPassword: "s3cr3t"},
	}), nil
}

func (f *fakeDataplaneClient) WorkerStream(context.Context) *connect.BidiStreamForClient[dataplanev1.WorkerMessage, dataplanev1.ServerMessage] {
	panic("unused")
}

var _ dataplanev1connect.DataplaneServiceClient = (*fakeDataplaneClient)(nil)

// TestHandleConnProxiesToPostgres drives handleConn end-to-end over a net.Pipe:
// CONNECT preamble -> pgwire startup -> (faked) PrepareSession redeem -> real dial
// to an ephemeral Postgres -> splice, and asserts SELECT 1 returns a row through
// the proxy. A deadline on the client side means any hang fails the test.
func TestHandleConnProxiesToPostgres(t *testing.T) {
	addr, db, leafFP, stop := startPostgres(t)
	defer stop()

	cliConn, srvConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleConn(ctx, srvConn, "pg-0", &fakeDataplaneClient{addr: addr, db: db, leafFP: leafFP},
		control.NewRegistry(), make(chan control.SessionEnd, 1), nil)
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

// mismatchClient returns a tls_leaf anchor pinned to a fingerprint the real target
// will NOT present, so the worker's observe cannot match any anchor.
type mismatchClient struct{ *fakeDataplaneClient }

func (c mismatchClient) PrepareSession(ctx context.Context, req *connect.Request[dataplanev1.PrepareSessionRequest]) (*connect.Response[dataplanev1.PrepareSessionResponse], error) {
	resp, _ := c.fakeDataplaneClient.PrepareSession(ctx, req)
	resp.Msg.TrustAnchors[0].Sha256Fingerprint = "SHA256:" + strings.Repeat("A", 43) // never the real leaf
	return resp, nil
}

// TestHandleConnRefusesOnIdentityMismatch is the handler-level ordering invariant:
// when the observed target identity matches no approved anchor, the worker rejects
// the client and NEVER calls IssueSessionCredential — no credential is requested,
// let alone released, before a successful match.
func TestHandleConnRefusesOnIdentityMismatch(t *testing.T) {
	addr, db, leafFP, stop := startPostgres(t)
	defer stop()

	fake := &fakeDataplaneClient{addr: addr, db: db, leafFP: leafFP}
	cliConn, srvConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleConn(ctx, srvConn, "pg-0", mismatchClient{fake},
		control.NewRegistry(), make(chan control.SessionEnd, 1), nil)
	defer func() { _ = cliConn.Close() }()

	if err := cliConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(cliConn)
	if _, err := io.WriteString(cliConn, "CONNECT asset HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT not established: %q err=%v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	fe := pgproto3.NewFrontend(br, cliConn)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush ssl: %v", err)
	}
	if b, err := br.ReadByte(); err != nil || b != 'N' {
		t.Fatalf("ssl decline: %q err=%v", b, err)
	}
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "app", "database": "appdb"}})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	// The worker must reject with a FATAL error, not authenticate.
	msg := waitFor[*pgproto3.ErrorResponse](t, fe)
	if msg.Severity != "FATAL" {
		t.Fatalf("want FATAL rejection, got %+v", msg)
	}
	if fake.issued != nil {
		t.Fatal("IssueSessionCredential was called despite no anchor match — credential requested before verification")
	}
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

// recordingClient is a fakeDataplaneClient whose PrepareSession also requires
// recording.
type recordingClient struct{ *fakeDataplaneClient }

func (c recordingClient) PrepareSession(ctx context.Context, req *connect.Request[dataplanev1.PrepareSessionRequest]) (*connect.Response[dataplanev1.PrepareSessionResponse], error) {
	resp, _ := c.fakeDataplaneClient.PrepareSession(ctx, req)
	resp.Msg.RecordingRequired = true
	resp.Msg.RecordingObjectKey = "recordings/postgres/2026/03/07/sess-1.ndjson"
	return resp, nil
}

type memUploader struct {
	mu   sync.Mutex
	key  string
	body []byte
}

func (m *memUploader) Put(_ context.Context, key string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key, m.body = key, append([]byte(nil), body...)
	return nil
}

func TestHandleConnRecordsTimeline(t *testing.T) {
	addr, db, leafFP, stop := startPostgres(t)
	defer stop()

	cliConn, srvConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	up := &memUploader{}
	ended := make(chan control.SessionEnd, 1)
	go handleConn(ctx, srvConn, "pg-0", recordingClient{&fakeDataplaneClient{addr: addr, db: db, leafFP: leafFP}},
		control.NewRegistry(), ended, up)
	defer func() { _ = cliConn.Close() }()

	if err := cliConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(cliConn)

	if _, err := io.WriteString(cliConn, "CONNECT asset HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT not established: %q err=%v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	fe := pgproto3.NewFrontend(br, cliConn)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush ssl: %v", err)
	}
	if b, err := br.ReadByte(); err != nil || b != 'N' {
		t.Fatalf("ssl decline: %q err=%v", b, err)
	}
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "app", "database": "appdb"}})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush startup: %v", err)
	}
	waitFor[*pgproto3.ReadyForQuery](t, fe)

	// Simple query.
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush query: %v", err)
	}
	waitFor[*pgproto3.CommandComplete](t, fe)
	waitFor[*pgproto3.ReadyForQuery](t, fe)

	// Extended protocol with a bound parameter whose VALUE must be redacted.
	fe.Send(&pgproto3.Parse{Query: "SELECT $1::int"})
	fe.Send(&pgproto3.Bind{Parameters: [][]byte{[]byte("4242")}})
	fe.Send(&pgproto3.Describe{ObjectType: 'P'})
	fe.Send(&pgproto3.Execute{})
	fe.Send(&pgproto3.Sync{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush extended: %v", err)
	}
	waitFor[*pgproto3.ReadyForQuery](t, fe)

	// End the session and wait for Finish to upload (Finish runs before the ended send).
	_ = cliConn.Close()
	select {
	case end := <-ended:
		if end.Recording == nil || end.Recording.GetStatus() != "completed" {
			t.Fatalf("recording = %+v, want completed", end.Recording)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for SessionEnd")
	}

	up.mu.Lock()
	body := string(up.body)
	up.mu.Unlock()

	for _, want := range []string{`"kind":"pg"`, `"type":"query"`, `"sql":"SELECT 1"`, `"type":"parse"`, `"type":"bind"`, `"type":"command_complete"`} {
		if !strings.Contains(body, want) {
			t.Errorf("timeline missing %s\n---\n%s", want, body)
		}
	}
	// NEVER the bound parameter value or any result-row data.
	if strings.Contains(body, "4242") {
		t.Errorf("timeline leaked bound param value 4242:\n%s", body)
	}
	// Every line must be valid JSON.
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("invalid NDJSON line %q: %v", line, err)
		}
	}
}
