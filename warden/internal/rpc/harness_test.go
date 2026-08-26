package rpc_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/ca"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// newServer spins up an ephemeral Postgres, migrates it, and mounts the full
// service set (user + mesh) on an httptest server. It returns the pool and URL.
func newServer(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	sealer := testSealer(t)
	sessionSvc, _ := testSessionService(t, pool, sealer)
	mux := http.NewServeMux()
	if err := registerServices(mux, pool, testAccessRequestService(pool), sealer, audit.New(pool), sessionSvc, nil, dataplane.NewRegistry(), &fakePresigner{}, time.Minute, true); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pool, srv.URL
}

// seedUser creates a local user with a password; admin=true also binds it to a global
// `**` role so the capability-gated management handlers admit it (mirrors
// bootstrap.EnsureAdmin).
func seedUser(t *testing.T, pool *pgxpool.Pool, email, pw string, admin bool) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)
	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	// Mirror bootstrap.EnsureAdmin: an admin also holds `**` globally via a scopeless
	// standing binding so the capability-gated management handlers admit it.
	if admin {
		role := createRoleWithCaps(t, ctx, q, "admin-"+uuid.NewString(), pgtype.UUID{}, `["**"]`)
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        role.ID,
			SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// emptySSHConfig is the minimal valid CreateAssetRequest config oneof: an SSH asset
// with no logins.
func emptySSHConfig() *catalogv1.CreateAssetRequest_Ssh {
	return &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{}}
}

// fakePresigner is a test presigner that returns a canned URL and a fixed
// expiry offset from now, recording the last object key it was asked to sign.
type fakePresigner struct{ lastKey string }

func (f *fakePresigner) PresignGet(_ context.Context, objectKey string, ttl time.Duration) (string, time.Time, error) {
	f.lastKey = objectKey
	return "https://recordings.test/get?key=" + objectKey, time.Now().Add(ttl), nil
}

// seedRecordingRow inserts a completed recording for (userID, assetID) and
// returns its session id.
func seedRecordingRow(t *testing.T, pool *pgxpool.Pool, userID, assetID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sessionID := uuid.New()
	if err := sqlc.New(pool).UpsertSessionRecording(ctx, sqlc.UpsertSessionRecordingParams{
		SessionID: sessionID,
		UserID:    userID,
		AssetID:   assetID,
		WorkerID:  "worker-1",
		Protocol:  "ssh",
		Format:    "asciicast",
		ObjectKey: "recordings/" + sessionID.String() + ".cast",
		SizeBytes: 1,
		Sha256:    "deadbeef",
		Status:    "completed",
		StartedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
		EndedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}); err != nil {
		t.Fatalf("seedRecordingRow: %v", err)
	}
	return sessionID
}

// meshTestCA is a test mesh CA with helpers to mint identity keypairs.
type meshTestCA struct {
	ca       *ca.MeshCA
	bundle   []byte
	certPool *x509.CertPool
}

func newMeshTestCA(t *testing.T) *meshTestCA {
	t.Helper()
	caKeyDER, caCertPEM, err := ca.GenerateMeshCA()
	if err != nil {
		t.Fatalf("generate mesh CA: %v", err)
	}
	mca, err := ca.LoadMeshCA(caKeyDER, caCertPEM)
	if err != nil {
		t.Fatalf("load mesh CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatalf("append CA cert to pool")
	}
	return &meshTestCA{ca: mca, bundle: caCertPEM, certPool: pool}
}

// mint issues a leaf keypair for the given spiffe identity and returns the PEM
// certificate/key plus a tls.Certificate ready for a TLS config.
func (m *meshTestCA) mint(t *testing.T, spiffe string) (certPEM, keyPEM []byte, tlsCert tls.Certificate) {
	t.Helper()
	keyDER, csrDER, err := ca.GenerateCSR(spiffe)
	if err != nil {
		t.Fatalf("generate CSR: %v", err)
	}
	leafPEM, _, err := m.ca.SignCSR(csrDER, spiffe, time.Hour)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 keypair: %v", err)
	}
	return leafPEM, keyPEM, cert
}

// assertPermissionDenied fails unless err is a Connect PermissionDenied.
func assertPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PermissionDenied, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v: %v", connect.CodeOf(err), err)
	}
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

// waitConnected polls until the registry reports the worker's connected state as
// want, or fails after a short deadline.
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
