package rpc_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// newDataplaneServer builds an rpc mux with the DataplaneService mounted over a
// real SetupService (backed by the test sealer + an initialized session signing
// key), returning the shared worker registry so tests can push teardown signals
// into a connected stream.
func newDataplaneServer(t *testing.T) (pool *pgxpool.Pool, url string, reg *dataplane.Registry) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(p.Close)

	sealer := testSealer(t)
	sessionSvc, pub := testSessionService(t, p, sealer)

	authorizer := authz.NewSQLAuthorizer(p)
	auditLog := audit.New(p)
	broker := vault.NewBroker(p, sealer, authorizer, auditLog)
	verifier := sessiontoken.NewVerifier(pub)
	setupSvc := dataplane.NewSetupService(p, verifier, authorizer, broker, auditLog, time.Hour)

	registry := dataplane.NewRegistry()
	mux := http.NewServeMux()
	if err := rpc.Register(mux, p, testAccessRequestService(p), sealer, sessionSvc, setupSvc, registry); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Bidi streaming requires HTTP/2; httptest defaults to HTTP/1.1. Enable
	// unencrypted (h2c) HTTP/2 on both server and client, matching main.go's
	// listener configuration.
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = &protos
	srv.Start()
	t.Cleanup(srv.Close)
	return p, srv.URL, registry
}

// h2cClient is an HTTP client that speaks unencrypted HTTP/2 (h2c), required for
// the worker bidi stream against the test server.
func h2cClient() *http.Client {
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &protos}}
}

func TestWorkerStreamRegisterAck(t *testing.T) {
	_, url, reg := newDataplaneServer(t)
	ctx := context.Background()

	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
	stream := client.WorkerStream(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })

	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
		Register: &dataplanev1.Register{WorkerId: "w1", Protocols: []string{"ssh"}, Capacity: 10},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}

	msg, err := stream.Receive()
	if err != nil {
		t.Fatalf("receive ack: %v", err)
	}
	if msg.GetAck() == nil {
		t.Fatalf("first server frame is not a RegisterAck: %+v", msg)
	}
	waitConnected(t, reg, "w1", true)
}

func TestWorkerStreamTeardownPush(t *testing.T) {
	_, url, reg := newDataplaneServer(t)
	ctx := context.Background()

	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
	stream := client.WorkerStream(ctx)

	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
		Register: &dataplanev1.Register{WorkerId: "w1"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	ack, err := stream.Receive()
	if err != nil {
		t.Fatalf("receive ack: %v", err)
	}
	if ack.GetAck() == nil {
		t.Fatalf("expected RegisterAck, got %+v", ack)
	}
	waitConnected(t, reg, "w1", true)

	if !reg.Push("w1", dataplane.Signal{SessionID: "s1", Reason: "revoked"}) {
		t.Fatal("Push to connected worker reported not delivered")
	}

	td, err := stream.Receive()
	if err != nil {
		t.Fatalf("receive teardown: %v", err)
	}
	teardown := td.GetTeardown()
	if teardown == nil {
		t.Fatalf("expected Teardown frame, got %+v", td)
	}
	if teardown.SessionId != "s1" || teardown.Reason != "revoked" {
		t.Fatalf("unexpected teardown: %+v", teardown)
	}

	// Half-close the request: the handler's recv goroutine sees io.EOF, the handler
	// returns, and the registry entry is removed.
	if err := stream.CloseRequest(); err != nil {
		t.Fatalf("close request: %v", err)
	}
	// Drain the response until the server closes it.
	for {
		if _, err := stream.Receive(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			break
		}
	}
	_ = stream.CloseResponse()
	waitConnected(t, reg, "w1", false)
}

func TestSetupSessionRPCUnauthenticated(t *testing.T) {
	_, url, _ := newDataplaneServer(t)
	ctx := context.Background()

	client := dataplanev1connect.NewDataplaneServiceClient(http.DefaultClient, url)
	_, err := client.SetupSession(ctx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken:       "not-a-real-token",
		WorkerId:           "w1",
		ClientSshPublicKey: []byte("bogus"),
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bogus-token SetupSession = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// waitConnected polls the registry until worker's connected state matches want, or
// fails after a short timeout (Add/Remove happen inside the handler goroutine).
func waitConnected(t *testing.T, reg *dataplane.Registry, workerID string, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Connected(workerID) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("registry.Connected(%q) never became %v", workerID, want)
}
