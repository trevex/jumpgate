package rpc_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	recordingv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1/recordingv1connect"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// fakePresigner is a test presigner that returns a canned URL and a fixed
// expiry offset from now, recording the last object key it was asked to sign.
type fakePresigner struct{ lastKey string }

func (f *fakePresigner) PresignGet(_ context.Context, objectKey string, ttl time.Duration) (string, time.Time, error) {
	f.lastKey = objectKey
	return "https://recordings.test/get?key=" + objectKey, time.Now().Add(ttl), nil
}

func TestRecordingServiceAdminFlow(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "bob@x", "password123", false)
	ctx := context.Background()
	q := gen.New(pool)

	// Seed a recording row.
	userID := userIDByEmail(t, pool, "bob@x")
	assetID := uuid.New()
	sessionID := uuid.New()
	started := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Millisecond)
	ended := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Millisecond)
	if err := q.UpsertSessionRecording(ctx, gen.UpsertSessionRecordingParams{
		SessionID: sessionID,
		UserID:    userID,
		AssetID:   assetID,
		WorkerID:  "worker-1",
		Protocol:  "ssh",
		Format:    "asciicast",
		ObjectKey: "recordings/" + sessionID.String() + ".cast",
		SizeBytes: 4242,
		Sha256:    "abc123",
		Status:    "completed",
		StartedAt: pgtype.Timestamptz{Time: started, Valid: true},
		EndedAt:   pgtype.Timestamptz{Time: ended, Valid: true},
	}); err != nil {
		t.Fatalf("upsert recording: %v", err)
	}

	adminTok := adminToken(t, url)
	bobTok := authClient(t, url, "bob@x", "password123")
	c := recordingv1connect.NewRecordingServiceClient(http.DefaultClient, url)

	// Non-admin ListRecordings → PermissionDenied.
	_, err := c.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{}), bobTok))
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied {
		t.Fatalf("non-admin ListRecordings code = %v, want PermissionDenied", code)
	}

	// Admin ListRecordings → returns the seeded recording.
	lr, err := c.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{}), adminTok))
	if err != nil {
		t.Fatalf("admin ListRecordings: %v", err)
	}
	if len(lr.Msg.Recordings) != 1 {
		t.Fatalf("ListRecordings len = %d, want 1", len(lr.Msg.Recordings))
	}
	if lr.Msg.Recordings[0].SessionId != sessionID.String() {
		t.Fatalf("ListRecordings session_id = %s, want %s", lr.Msg.Recordings[0].SessionId, sessionID)
	}

	// Admin GetRecording → round-trips metadata.
	gr, err := c.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessionID.String()}), adminTok))
	if err != nil {
		t.Fatalf("admin GetRecording: %v", err)
	}
	rec := gr.Msg
	if rec.UserId != userID.String() || rec.AssetId != assetID.String() {
		t.Fatalf("GetRecording ids mismatch: %+v", rec)
	}
	if rec.Protocol != "ssh" || rec.Format != "asciicast" || rec.Status != "completed" {
		t.Fatalf("GetRecording fields mismatch: %+v", rec)
	}
	if rec.SizeBytes != 4242 || rec.Sha256 != "abc123" {
		t.Fatalf("GetRecording size/sha mismatch: %+v", rec)
	}
	if rec.StartedAtUnixMs != started.UnixMilli() || rec.EndedAtUnixMs != ended.UnixMilli() {
		t.Fatalf("GetRecording timestamps mismatch: got start=%d end=%d want start=%d end=%d",
			rec.StartedAtUnixMs, rec.EndedAtUnixMs, started.UnixMilli(), ended.UnixMilli())
	}

	// Admin GetRecordingDownload → non-empty url + recording.accessed audit event.
	dl, err := c.GetRecordingDownload(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessionID.String()}), adminTok))
	if err != nil {
		t.Fatalf("admin GetRecordingDownload: %v", err)
	}
	if dl.Msg.Url == "" {
		t.Fatalf("GetRecordingDownload url is empty")
	}
	if dl.Msg.ExpiresAtUnixMs == 0 {
		t.Fatalf("GetRecordingDownload expires_at_unix_ms is 0")
	}

	// Drain the audit outbox and assert a recording.accessed event is present.
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
	rows, err := q.ListAuditEntries(ctx)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	found := 0
	for _, r := range rows {
		if r.EventType == dataplane.EventRecordingAccessed {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("recording.accessed count = %d, want 1", found)
	}
}

// userIDByEmail looks up a seeded user's id by email.
func userIDByEmail(t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatalf("lookup user %s: %v", email, err)
	}
	return id
}
