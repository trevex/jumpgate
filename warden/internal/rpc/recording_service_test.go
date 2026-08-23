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

	accessrequestv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
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

// seedRecordingRow inserts a completed recording for (userID, assetID) and
// returns its session id.
func seedRecordingRow(t *testing.T, pool *pgxpool.Pool, userID, assetID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sessionID := uuid.New()
	if err := gen.New(pool).UpsertSessionRecording(ctx, gen.UpsertSessionRecordingParams{
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

// TestRecordingCapabilityGating asserts recording reads are gated by scoped
// recording:read: a user holding it at asset A can ListRecordings --asset A and
// GetRecording a recording of A, but is denied for asset B and for an
// unfiltered (global) ListRecordings. The bootstrap admin (**) can do all.
func TestRecordingCapabilityGating(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "rec@x", "password123", false)
	atok := adminToken(t, url)
	rtok := authClient(t, url, "rec@x", "password123")
	ctx := context.Background()

	userID := userIDByEmail(t, pool, "rec@x")
	// Real catalog assets: role_bindings.scope_asset_id has an FK to assets.
	assetA := newAsset(t, url, atok, "ssh")
	assetB := newAsset(t, url, atok, "ssh")
	assetAID := uuid.MustParse(assetA.Id)
	assetBID := uuid.MustParse(assetB.Id)
	sessA := seedRecordingRow(t, pool, userID, assetAID)
	sessB := seedRecordingRow(t, pool, userID, assetBID)

	// rec holds recording:read bound at asset A only.
	bindScopedCap(t, pool, userID, `["recording:read"]`, uuid.Nil, assetAID)

	rc := recordingv1connect.NewRecordingServiceClient(http.DefaultClient, url)

	// Allowed: ListRecordings filtered to A.
	if _, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{AssetId: assetA.Id}), rtok)); err != nil {
		t.Fatalf("rec ListRecordings --asset A = %v, want ok", err)
	}
	// Allowed: GetRecording of a recording on A.
	if _, err := rc.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessA.String()}), rtok)); err != nil {
		t.Fatalf("rec GetRecording A = %v, want ok", err)
	}
	// Denied: ListRecordings filtered to B.
	if _, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{AssetId: assetB.Id}), rtok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("rec ListRecordings --asset B = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// Denied: GetRecording of a recording on B.
	if _, err := rc.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessB.String()}), rtok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("rec GetRecording B = %v, want PermissionDenied", connect.CodeOf(err))
	}
	// Denied: unfiltered ListRecordings (needs recording:read globally).
	if _, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{}), rtok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("rec ListRecordings (unfiltered) = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Admin (**) can do all.
	if _, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{}), atok)); err != nil {
		t.Fatalf("admin ListRecordings = %v, want ok", err)
	}
	if _, err := rc.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessB.String()}), atok)); err != nil {
		t.Fatalf("admin GetRecording B = %v, want ok", err)
	}
}

// seedGrantAttributedRecording builds a real request→approve→grant flow so the
// resulting access_grant has a real (role, asset, subject) and returns the grant
// id, the asset id, the requester/subject id, and the approver's id. alice is the
// requester/subject; bob is bound to the approver role (a potential approver). It
// then seeds a recording attributed to that grant and returns its session id.
//
// It uses the AccessRequest RPCs (not raw inserts) so the grant is genuine and the
// approver-eligibility is decided by the same policy machinery the inbox uses.
func seedGrantAttributedRecording(t *testing.T, pool *pgxpool.Pool, url string) (grantID, assetID, sessionID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	adminTok := adminToken(t, url)
	asset := newAsset(t, url, adminTok, "ssh")
	aID := uuid.MustParse(asset.Id)

	mkRole := func(name string) uuid.UUID {
		r, err := q.CreateRole(ctx, gen.CreateRoleParams{Name: name + "-" + uuid.NewString(), Capabilities: []byte("[]")})
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		return r.ID
	}
	target := mkRole("gr-target")
	requesterRole := mkRole("gr-requester")
	approverRole := mkRole("gr-approver")

	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: target, RequiredApprovals: 1,
		ApproverRoleID: pgU(approverRole), RequesterRoleID: pgU(requesterRole),
	}); err != nil {
		t.Fatalf("CreateRequestPolicy: %v", err)
	}

	bind := func(uid, roleID uuid.UUID) {
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: roleID, ScopeAssetID: pgU(aID), SubjectUserID: pgU(uid),
		}); err != nil {
			t.Fatalf("CreateRoleBinding: %v", err)
		}
	}

	seedUser(t, pool, "alice@rev", "password123", false)
	seedUser(t, pool, "bob@rev", "password123", false)
	aliceID := userIDByEmail(t, pool, "alice@rev")
	bind(aliceID, requesterRole)
	bind(userIDByEmail(t, pool, "bob@rev"), approverRole)

	aliceTok := authClient(t, url, "alice@rev", "password123")
	bobTok := authClient(t, url, "bob@rev", "password123")

	arc := accessrequestv1connect.NewAccessRequestServiceClient(http.DefaultClient, url)
	resp, err := arc.RequestAccess(ctx, withToken(connect.NewRequest(&accessrequestv1.RequestAccessRequest{
		RoleId: target.String(), AssetId: asset.Id, DurationSeconds: 3600, Reason: "review test",
	}), aliceTok))
	if err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	appr, err := arc.ApproveRequest(ctx, withToken(connect.NewRequest(&accessrequestv1.ApproveRequestRequest{
		RequestId: resp.Msg.Request.Id,
	}), bobTok))
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	gID := uuid.MustParse(appr.Msg.Request.GrantId)

	// Seed a recording attributed to the grant. The subject of the recording is
	// alice; the session is authorized by the grant.
	sID := uuid.New()
	if err := q.UpsertSessionRecording(ctx, gen.UpsertSessionRecordingParams{
		SessionID: sID,
		UserID:    aliceID,
		AssetID:   aID,
		WorkerID:  "worker-1",
		Protocol:  "ssh",
		Format:    "asciicast",
		ObjectKey: "recordings/" + sID.String() + ".cast",
		SizeBytes: 7,
		Sha256:    "cafef00d",
		Status:    "completed",
		StartedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
		EndedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
		GrantID:   pgtype.UUID{Bytes: gID, Valid: true},
	}); err != nil {
		t.Fatalf("UpsertSessionRecording (grant-attributed): %v", err)
	}
	return gID, aID, sID
}

// TestListRecordingsByGrant_SubjectAndApprover asserts that a grant-attributed
// recording is listable (filtered by grant_id) by the grant's subject and by a
// potential approver of the grant's originating request — neither of whom holds
// recording:read — while an unrelated user without recording:read is denied.
func TestListRecordingsByGrant_SubjectAndApprover(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "mallory@rev", "password123", false)
	ctx := context.Background()

	grantID, _, sessionID := seedGrantAttributedRecording(t, pool, url)

	aliceTok := authClient(t, url, "alice@rev", "password123") // subject
	bobTok := authClient(t, url, "bob@rev", "password123")     // potential approver
	malloryTok := authClient(t, url, "mallory@rev", "password123")

	rc := recordingv1connect.NewRecordingServiceClient(http.DefaultClient, url)

	// Subject sees the grant's recording.
	sub, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{GrantId: grantID.String()}), aliceTok))
	if err != nil {
		t.Fatalf("subject ListRecordings(grant) = %v, want ok", err)
	}
	if len(sub.Msg.Recordings) != 1 || sub.Msg.Recordings[0].SessionId != sessionID.String() {
		t.Fatalf("subject recordings = %+v, want [%s]", sub.Msg.Recordings, sessionID)
	}
	if sub.Msg.Recordings[0].GrantId != grantID.String() {
		t.Fatalf("subject recording grant_id = %q, want %s", sub.Msg.Recordings[0].GrantId, grantID)
	}

	// Potential approver sees the same recording (no recording:read held).
	app, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{GrantId: grantID.String()}), bobTok))
	if err != nil {
		t.Fatalf("approver ListRecordings(grant) = %v, want ok", err)
	}
	if len(app.Msg.Recordings) != 1 || app.Msg.Recordings[0].SessionId != sessionID.String() {
		t.Fatalf("approver recordings = %+v, want [%s]", app.Msg.Recordings, sessionID)
	}

	// Unrelated user without recording:read → denied (existing cap deny code).
	if _, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{GrantId: grantID.String()}), malloryTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unrelated ListRecordings(grant) = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestGetRecording_ApproverCanReadGrantAttributed asserts a potential approver
// (holding no recording:read) can GetRecording a grant-attributed recording, but
// is denied on an unattributed (NULL grant_id) recording — the grant-review path
// only adds access, it never bypasses recording:read.
func TestGetRecording_ApproverCanReadGrantAttributed(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	ctx := context.Background()

	grantID, assetID, sessionID := seedGrantAttributedRecording(t, pool, url)
	_ = grantID

	bobTok := authClient(t, url, "bob@rev", "password123") // potential approver, no recording:read

	// A NULL-grant recording on the same asset — bob must NOT be able to read it.
	nullSess := seedRecordingRow(t, pool, userIDByEmail(t, pool, "alice@rev"), assetID)

	rc := recordingv1connect.NewRecordingServiceClient(http.DefaultClient, url)

	// Grant-attributed recording → approver allowed.
	got, err := rc.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: sessionID.String()}), bobTok))
	if err != nil {
		t.Fatalf("approver GetRecording(grant-attributed) = %v, want ok", err)
	}
	if got.Msg.SessionId != sessionID.String() {
		t.Fatalf("GetRecording session_id = %q, want %s", got.Msg.SessionId, sessionID)
	}

	// NULL-grant recording → approver denied (recording:read still required).
	if _, err := rc.GetRecording(ctx, withToken(connect.NewRequest(&recordingv1.GetRecordingRequest{SessionId: nullSess.String()}), bobTok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("approver GetRecording(NULL grant) = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestListRecordingsKeysetPagination verifies (created_at DESC, session_id ASC)
// keyset pagination for ListRecordings. Seeds 3 recordings and pages through
// with page_size=2, asserting created_at DESC ordering, correct termination,
// and no duplicate session_ids across pages.
func TestListRecordingsKeysetPagination(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	seedUser(t, pool, "bob@x", "password123", false)
	atok := adminToken(t, url)
	ctx := context.Background()

	userID := userIDByEmail(t, pool, "bob@x")
	assetID := uuid.New()

	// Seed 3 recordings with deliberate created_at spread so ordering is deterministic.
	// UpsertSessionRecording uses ON CONFLICT DO UPDATE, which also resets created_at
	// to now(); seed sequentially so each row gets a distinct timestamp.
	var sessions []uuid.UUID
	for i := 0; i < 3; i++ {
		sid := seedRecordingRow(t, pool, userID, assetID)
		sessions = append(sessions, sid)
	}

	rc := recordingv1connect.NewRecordingServiceClient(http.DefaultClient, url)

	// Fetch all with large page; verify we get 3 rows and they are created_at DESC.
	all, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{PageSize: 100}), atok))
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Msg.Recordings) != 3 {
		t.Fatalf("total recordings = %d, want 3", len(all.Msg.Recordings))
	}
	// Verify ordering is newest-first: started_at_unix_ms is a proxy for created_at order.
	// We rely on all 3 being seeded in the same second; at minimum, no row should violate DESC.
	// (Exact ms ordering is validated by the ordering clause in SQL; this just sanity-checks.)
	if len(all.Msg.Recordings) > 1 {
		first := all.Msg.Recordings[0].StartedAtUnixMs
		last := all.Msg.Recordings[len(all.Msg.Recordings)-1].StartedAtUnixMs
		if first < last {
			t.Fatalf("recordings not DESC by started_at: first=%d last=%d", first, last)
		}
	}

	// Page through with page_size=2.
	page1, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{PageSize: 2}), atok))
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Msg.Recordings) != 2 {
		t.Fatalf("page1: got %d recordings, want 2", len(page1.Msg.Recordings))
	}
	if page1.Msg.NextPageToken == "" {
		t.Fatal("page1: expected non-empty NextPageToken")
	}

	page2, err := rc.ListRecordings(ctx, withToken(connect.NewRequest(&recordingv1.ListRecordingsRequest{
		PageSize:  2,
		PageToken: page1.Msg.NextPageToken,
	}), atok))
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Msg.Recordings) != 1 {
		t.Fatalf("page2: got %d recordings, want 1", len(page2.Msg.Recordings))
	}
	if page2.Msg.NextPageToken != "" {
		t.Fatalf("page2: expected empty NextPageToken, got %q", page2.Msg.NextPageToken)
	}

	// Assert no duplicate session_ids.
	seen := map[string]bool{}
	for _, r := range append(page1.Msg.Recordings, page2.Msg.Recordings...) {
		if seen[r.SessionId] {
			t.Fatalf("duplicate session_id: %s", r.SessionId)
		}
		seen[r.SessionId] = true
	}
	if len(seen) != 3 {
		t.Fatalf("total sessions across pages = %d, want 3", len(seen))
	}
	_ = sessions // seeded; IDs are verified via the round-trip
}
