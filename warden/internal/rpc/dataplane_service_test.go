package rpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	dataplanev1 "github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/session"
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
	_, pub := testSessionService(t, p, sealer)

	authorizer := authz.NewSQLAuthorizer(p)
	auditLog := audit.New(p)
	broker := vault.NewBroker(p, sealer, authorizer, auditLog)
	verifier := sessiontoken.NewVerifier(pub)
	setupSvc := dataplane.NewSetupService(p, verifier, authorizer, broker, auditLog, time.Hour)

	registry := dataplane.NewRegistry()
	mux := http.NewServeMux()
	if err := registerMeshServices(mux, p, auditLog, setupSvc, registry, pub); err != nil {
		t.Fatalf("register mesh: %v", err)
	}

	// Bidi streaming requires HTTP/2; httptest defaults to HTTP/1.1. Enable
	// unencrypted (h2c) HTTP/2 on both server and client, matching main.go's
	// listener configuration. These tests dial over plain h2c (no mTLS), so wrap the
	// mesh mux to inject the fixed worker "w1" identity mesh.Middleware would derive
	// from a cert SAN in production.
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(withTestWorkerIdentity(mux, "w1"))
	srv.Config.Protocols = &protos
	srv.Start()
	t.Cleanup(srv.Close)
	return p, srv.URL, registry
}

// withTestWorkerIdentity wraps next so every request carries a fixed worker mesh
// identity. It stands in for mesh.Middleware on the plain-h2c test servers (which
// have no client cert to derive a SAN from), letting the identity-enforcing
// Dataplane handlers run against a known worker id.
func withTestWorkerIdentity(next http.Handler, workerID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := mesh.WithIdentity(r.Context(), mesh.Identity{Role: "worker", ID: workerID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
		Login:              "deploy",
		ClientSshPublicKey: []byte("bogus"),
		TargetPublicKey:    []byte("bogus"),
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bogus-token SetupSession = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestSetupSessionRPCSurfacesRecording drives a full happy-path SetupSession over
// the RPC surface and asserts the response carries the recording requirement the
// SetupService computed: recording is mandatory by default (no exemption seeded),
// with a well-formed, session-scoped object key.
func TestSetupSessionRPCSurfacesRecording(t *testing.T) {
	ctx := context.Background()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := sqlc.New(pool)

	sealer := testSealer(t)

	// Active session signing key → minter (this test) + verifier (setup svc).
	ks := session.NewKeyStore(sqlc.New(pool), sealer)
	if err := ks.Init(ctx); err != nil {
		t.Fatalf("keystore init: %v", err)
	}
	priv, pub, err := ks.LoadActive(ctx)
	if err != nil {
		t.Fatalf("keystore load: %v", err)
	}
	minter := sessiontoken.NewMinter(priv)
	verifier := sessiontoken.NewVerifier(pub)

	// SSH CA (sealed seed) so the broker can mint the target-hop cert.
	seed, line, err := ca.GenerateSSHCA()
	if err != nil {
		t.Fatalf("GenerateSSHCA: %v", err)
	}
	sealedSeed, err := sealer.Seal(seed)
	if err != nil {
		t.Fatalf("seal ca seed: %v", err)
	}
	if _, err := q.CreateCAKey(ctx, sqlc.CreateCAKeyParams{Kind: "ssh", Sealed: sealedSeed, PublicMaterial: line}); err != nil {
		t.Fatalf("CreateCAKey: %v", err)
	}

	authorizer := authz.NewSQLAuthorizer(pool)
	auditLog := audit.New(pool)
	broker := vault.NewBroker(pool, sealer, authorizer, auditLog)
	setupSvc := dataplane.NewSetupService(pool, verifier, authorizer, broker, auditLog, time.Hour)

	registry := dataplane.NewRegistry()
	mux := http.NewServeMux()
	if err := registerMeshServices(mux, pool, auditLog, setupSvc, registry, pub); err != nil {
		t.Fatalf("register mesh: %v", err)
	}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(withTestWorkerIdentity(mux, "w1"))
	srv.Config.Protocols = &protos
	srv.Start()
	t.Cleanup(srv.Close)

	// Seed an ssh asset (target + allowed_logins {deploy}) and a role carrying
	// ssh:login:deploy standing-bound to the user — the sole login source.
	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-rec-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg-rec", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, sqlc.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.7:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "deploy", Kind: "ca", SecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}
	role := createRoleWithCaps(t, ctx, q, "ssh-deploy-rec-"+uuid.NewString(), pgtype.UUID{}, `["ssh:login:deploy"]`)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgtype.UUID{Bytes: asset.ID, Valid: true}, SubjectUserID: pgtype.UUID{Bytes: user.ID, Valid: true},
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}

	// Client ephemeral key (cnf-bound in the token) + worker per-session key (certified).
	_, cpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	cpub, err := ssh.NewPublicKey(cpriv.Public())
	if err != nil {
		t.Fatalf("ssh client pub: %v", err)
	}
	clientPub := ssh.MarshalAuthorizedKey(cpub)
	clientFp := ssh.FingerprintSHA256(cpub)

	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen worker key: %v", err)
	}
	wpub, err := ssh.NewPublicKey(wpriv.Public())
	if err != nil {
		t.Fatalf("ssh worker pub: %v", err)
	}
	workerPub := ssh.MarshalAuthorizedKey(wpub)

	sessionID := uuid.New()
	tok, err := minter.Mint(sessiontoken.Claims{
		SessionID:            sessionID,
		UserID:               user.ID,
		AssetID:              asset.ID,
		Protocol:             "ssh",
		ClientKeyFingerprint: clientFp,
	}, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), srv.URL)
	resp, err := client.SetupSession(ctx, connect.NewRequest(&dataplanev1.SetupSessionRequest{
		SessionToken: tok, WorkerId: "w1", Login: "deploy", ClientSshPublicKey: clientPub, TargetPublicKey: workerPub,
	}))
	if err != nil {
		t.Fatalf("SetupSession: %v", err)
	}
	if resp.Msg.GetSessionId() != sessionID.String() {
		t.Fatalf("SessionId = %q, want %q", resp.Msg.GetSessionId(), sessionID.String())
	}
	if !resp.Msg.GetRecordingRequired() {
		t.Fatal("RecordingRequired = false, want true (recording is mandatory by default)")
	}
	key := resp.Msg.GetRecordingObjectKey()
	if !strings.HasPrefix(key, "recordings/ssh/") {
		t.Fatalf("RecordingObjectKey = %q, want prefix recordings/ssh/", key)
	}
	if !strings.HasSuffix(key, "/"+sessionID.String()+".cast") {
		t.Fatalf("RecordingObjectKey = %q, want suffix /%s.cast", key, sessionID.String())
	}
}

// reconcileSeed is a minimal seed for the reconnect re-sync scenarios: an ssh asset
// (allowed_logins {deploy}, target set), a role carrying ssh:login:deploy conferred
// to a user via an active JIT grant, and a live_sessions row owned by "w1".
type reconcileSeed struct {
	user  uuid.UUID
	asset uuid.UUID
	grant uuid.UUID
	sess  uuid.UUID
}

func seedReconcile(t *testing.T, pool *pgxpool.Pool) reconcileSeed {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: uuid.NewString() + "@x", DisplayName: "U"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-recon-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "pg-recon", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := q.UpsertSSHAssetConfig(ctx, sqlc.UpsertSSHAssetConfigParams{
		AssetID: asset.ID, TargetAddress: "10.0.0.5:22",
	}); err != nil {
		t.Fatalf("UpsertSSHAssetConfig: %v", err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{
		AssetID: asset.ID, Login: "deploy", Kind: "ca", SecretID: pgtype.UUID{},
	}); err != nil {
		t.Fatalf("UpsertSSHAssetLogin: %v", err)
	}

	role := createRoleWithCaps(t, ctx, q, "ssh-deploy-"+uuid.NewString(), pgtype.UUID{}, `["ssh:login:deploy"]`)

	req, err := q.CreateAccessRequest(ctx, sqlc.CreateAccessRequestParams{
		RequesterUserID:   user.ID,
		RoleID:            role.ID,
		AssetID:           asset.ID,
		Reason:            "seed",
		RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		RequiredApprovals: 0,
		GrantedDuration:   pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		Status:            "granted",
	})
	if err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	grant, err := q.CreateAccessGrant(ctx, sqlc.CreateAccessGrantParams{
		RequestID: req.ID, RoleID: role.ID, ScopeAssetID: asset.ID, SubjectUserID: user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}

	sess, err := q.InsertLiveSession(ctx, sqlc.InsertLiveSessionParams{
		ID: uuid.New(), UserID: user.ID, AssetID: asset.ID, WorkerID: "w1",
		GrantID: pgtype.UUID{Bytes: grant.ID, Valid: true}, Protocol: "ssh", Principals: []string{"deploy"}, ClientKeyFp: "fp",
	})
	if err != nil {
		t.Fatalf("InsertLiveSession: %v", err)
	}
	return reconcileSeed{user: user.ID, asset: asset.ID, grant: grant.ID, sess: sess.ID}
}

// registerWorker opens a WorkerStream, sends Register with the given live-session IDs,
// and waits for the RegisterAck. The caller keeps the stream open (cleanup closes it).
func registerWorker(t *testing.T, url string, liveIDs []string) {
	t.Helper()
	ctx := context.Background()
	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
	stream := client.WorkerStream(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })

	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
		Register: &dataplanev1.Register{WorkerId: "w1", LiveSessionIds: liveIDs},
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
}

// sessionEventCount drains the outbox and counts audit entries of the given type.
func sessionEventCount(t *testing.T, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	ctx := context.Background()
	log := audit.New(pool)
	for {
		n, err := log.DrainOnce(ctx, 256)
		if err != nil {
			t.Fatalf("DrainOnce: %v", err)
		}
		if n < 256 {
			break
		}
	}
	rows, err := sqlc.New(pool).ListAuditEntries(ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.EventType == eventType {
			n++
		}
	}
	return n
}

// TestReconcileMarksEndedWhenWorkerDroppedSession: a worker (re)registers reporting NO
// live sessions, but warden has a DB row for it. The reconnect re-sync must mark that
// session ended — delete the row and emit session.ended.
func TestReconcileMarksEndedWhenWorkerDroppedSession(t *testing.T) {
	pool, url, _ := newDataplaneServer(t)
	seed := seedReconcile(t, pool)

	registerWorker(t, url, nil) // worker reports no sessions

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM live_sessions WHERE id = $1`, seed.sess).Scan(&n); err != nil {
			t.Fatalf("count live_sessions: %v", err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconcile did not delete the dropped session's live_sessions row")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := sessionEventCount(t, pool, dataplane.EventSessionEnded); n != 1 {
		t.Fatalf("session.ended events = %d, want 1", n)
	}
	if err := audit.New(pool).Verify(ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestReconcileTearsDownUnauthorizedRetainedSession: the worker still reports the
// session, but its authorization was revoked while the stream was down. The reconnect
// re-sync must re-evaluate and tear it down — mark terminating + emit session.terminated.
func TestReconcileTearsDownUnauthorizedRetainedSession(t *testing.T) {
	pool, url, _ := newDataplaneServer(t)
	seed := seedReconcile(t, pool)

	ctx := context.Background()
	// Revoke the sole login source before the worker reconnects.
	if _, err := pool.Exec(ctx, `UPDATE access_grants SET revoked_at = now() WHERE id = $1`, seed.grant); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	registerWorker(t, url, []string{seed.sess.String()}) // worker still has it

	deadline := time.Now().Add(2 * time.Second)
	for {
		var ts pgtype.Timestamptz
		if err := pool.QueryRow(ctx, `SELECT terminate_requested_at FROM live_sessions WHERE id = $1`, seed.sess).Scan(&ts); err != nil {
			t.Fatalf("select terminate_requested_at: %v", err)
		}
		if ts.Valid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconcile did not set terminate_requested_at on the unauthorized retained session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := sessionEventCount(t, pool, dataplane.EventSessionTerminated); n != 1 {
		t.Fatalf("session.terminated events = %d, want 1", n)
	}
	if err := audit.New(pool).Verify(ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestWorkerSessionEndedDeletesRow: a worker holds an authorized live session (its
// login source is still active, so the reconnect re-sync keeps the row on Register).
// When the worker then reports SessionEnded, warden deletes the live_sessions row and
// audits exactly one session.ended.
func TestWorkerSessionEndedDeletesRow(t *testing.T) {
	pool, url, _ := newDataplaneServer(t)
	seed := seedReconcile(t, pool) // grant is active → still authorized at register time

	ctx := context.Background()
	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
	stream := client.WorkerStream(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })

	// Register reporting the session as still live so reconcile re-evaluates and,
	// finding it authorized, keeps the row — the SessionEnded frame is what deletes it.
	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
		Register: &dataplanev1.Register{WorkerId: "w1", LiveSessionIds: []string{seed.sess.String()}},
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

	// Row must still exist after Ack (reconcile kept the authorized session).
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM live_sessions WHERE id = $1`, seed.sess).Scan(&n); err != nil {
		t.Fatalf("count live_sessions after ack: %v", err)
	}
	if n != 1 {
		t.Fatalf("live_sessions row missing after ack (reconcile pre-empted the test): count=%d", n)
	}

	// Worker reports the session ended.
	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_SessionEnded{
		SessionEnded: &dataplanev1.SessionEnded{SessionId: seed.sess.String(), Reason: "closed"},
	}}); err != nil {
		t.Fatalf("send session-ended: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM live_sessions WHERE id = $1`, seed.sess).Scan(&n); err != nil {
			t.Fatalf("count live_sessions: %v", err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SessionEnded did not delete the live_sessions row")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := sessionEventCount(t, pool, dataplane.EventSessionEnded); got != 1 {
		t.Fatalf("session.ended events = %d, want 1", got)
	}
	if err := audit.New(pool).Verify(ctx); err != nil {
		t.Fatalf("audit Verify: %v", err)
	}
}

// TestWorkerSessionEndedPersistsRecording drives a WorkerStream: a worker holds an
// authorized live session (seeded), then reports SessionEnded carrying a RecordingInfo.
// warden must persist a session_recordings row (with the session's parties, protocol
// "ssh", format "asciicast-v2") and audit recording.completed / recording.failed.
func TestWorkerSessionEndedPersistsRecording(t *testing.T) {
	cases := []struct {
		name       string
		status     string
		wantStatus string
		wantEvent  string
	}{
		{name: "completed", status: "completed", wantStatus: "completed", wantEvent: dataplane.EventRecordingCompleted},
		{name: "failed", status: "failed", wantStatus: "failed", wantEvent: dataplane.EventRecordingFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, url, _ := newDataplaneServer(t)
			seed := seedReconcile(t, pool)

			ctx := context.Background()
			client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
			stream := client.WorkerStream(ctx)
			t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })

			// Register reporting the session as still live so reconcile keeps the row.
			if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
				Register: &dataplanev1.Register{WorkerId: "w1", LiveSessionIds: []string{seed.sess.String()}},
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

			objectKey := "recordings/ssh/2026/08/19/" + seed.sess.String() + ".cast"
			startedMs := time.Now().Add(-time.Minute).UnixMilli()
			endedMs := time.Now().UnixMilli()
			if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_SessionEnded{
				SessionEnded: &dataplanev1.SessionEnded{
					SessionId: seed.sess.String(),
					Reason:    "closed",
					Recording: &dataplanev1.RecordingInfo{
						Status:          tc.status,
						ObjectKey:       objectKey,
						Sha256:          "abc",
						SizeBytes:       123,
						StartedAtUnixMs: startedMs,
						EndedAtUnixMs:   endedMs,
					},
				},
			}}); err != nil {
				t.Fatalf("send session-ended: %v", err)
			}

			// Poll until the recording row appears.
			var rec sqlc.SessionRecording
			deadline := time.Now().Add(2 * time.Second)
			for {
				rec, err = sqlc.New(pool).GetSessionRecording(ctx, seed.sess)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("session_recordings row never appeared: %v", err)
				}
				time.Sleep(20 * time.Millisecond)
			}

			if rec.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", rec.Status, tc.wantStatus)
			}
			if rec.ObjectKey != objectKey {
				t.Errorf("object_key = %q, want %q", rec.ObjectKey, objectKey)
			}
			if rec.Sha256 != "abc" {
				t.Errorf("sha256 = %q, want abc", rec.Sha256)
			}
			if rec.SizeBytes != 123 {
				t.Errorf("size_bytes = %d, want 123", rec.SizeBytes)
			}
			if rec.UserID != seed.user {
				t.Errorf("user_id = %v, want %v", rec.UserID, seed.user)
			}
			if rec.AssetID != seed.asset {
				t.Errorf("asset_id = %v, want %v", rec.AssetID, seed.asset)
			}
			if rec.Protocol != "ssh" {
				t.Errorf("protocol = %q, want ssh", rec.Protocol)
			}
			if rec.Format != "asciicast-v2" {
				t.Errorf("format = %q, want asciicast-v2", rec.Format)
			}
			if !rec.StartedAt.Valid || !rec.EndedAt.Valid {
				t.Errorf("started_at/ended_at not set: %+v / %+v", rec.StartedAt, rec.EndedAt)
			}

			if got := sessionEventCount(t, pool, tc.wantEvent); got != 1 {
				t.Fatalf("%s events = %d, want 1", tc.wantEvent, got)
			}
			if err := audit.New(pool).Verify(ctx); err != nil {
				t.Fatalf("audit Verify: %v", err)
			}
		})
	}
}

// TestWorkerSessionEndedPersistsRecordingGrantID drives a WorkerStream reporting a
// SessionEnded whose RecordingInfo carries a grant_id (the JIT grant that authorized
// the session). warden must attribute the recording to that grant — persist it onto
// the session_recordings row's grant_id column (FK to access_grants).
func TestWorkerSessionEndedPersistsRecordingGrantID(t *testing.T) {
	pool, url, _ := newDataplaneServer(t)
	seed := seedReconcile(t, pool) // seeds a real access_grants row (seed.grant) + live session

	ctx := context.Background()
	client := dataplanev1connect.NewDataplaneServiceClient(h2cClient(), url)
	stream := client.WorkerStream(ctx)
	t.Cleanup(func() { _ = stream.CloseRequest(); _ = stream.CloseResponse() })

	// Register reporting the session as still live so reconcile keeps the row.
	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_Register{
		Register: &dataplanev1.Register{WorkerId: "w1", LiveSessionIds: []string{seed.sess.String()}},
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

	objectKey := "recordings/ssh/2026/08/19/" + seed.sess.String() + ".cast"
	if err := stream.Send(&dataplanev1.WorkerMessage{Msg: &dataplanev1.WorkerMessage_SessionEnded{
		SessionEnded: &dataplanev1.SessionEnded{
			SessionId: seed.sess.String(),
			Reason:    "closed",
			Recording: &dataplanev1.RecordingInfo{
				Status:    "completed",
				ObjectKey: objectKey,
				GrantId:   seed.grant.String(),
			},
		},
	}}); err != nil {
		t.Fatalf("send session-ended: %v", err)
	}

	// Poll until the recording row appears, then assert grant_id attribution.
	var rec sqlc.SessionRecording
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec, err = sqlc.New(pool).GetSessionRecording(ctx, seed.sess)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session_recordings row never appeared: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !rec.GrantID.Valid {
		t.Fatalf("session_recordings.grant_id is NULL, want %s", seed.grant)
	}
	if got := uuid.UUID(rec.GrantID.Bytes); got != seed.grant {
		t.Fatalf("session_recordings.grant_id = %s, want %s", got, seed.grant)
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
