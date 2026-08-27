package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// ─── fakes ───────────────────────────────────────────────────────────────────

// fakeObjectGetter returns a fixed body or an error.
type fakeObjectGetter struct {
	body    string
	failErr error
}

func (f *fakeObjectGetter) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.failErr != nil {
		return nil, f.failErr
	}
	return io.NopCloser(strings.NewReader(f.body)), nil
}

// fakeGrantReviewer authorizes review iff (caller, grantID) is in the allow set.
type fakeGrantReviewer struct{ allow map[[2]uuid.UUID]bool }

func (f *fakeGrantReviewer) CanReviewGrant(_ context.Context, caller, grantID uuid.UUID) (bool, error) {
	return f.allow[[2]uuid.UUID{caller, grantID}], nil
}

// ─── test server helpers ──────────────────────────────────────────────────────

// castServer starts a test HTTP server with the cast route mounted via
// the full NewRouter + RouterDeps path. It returns the server URL, the DB
// pool (for seeding), and the auth.Lookup for issuing tokens.
func castServer(t *testing.T, getter httpapi.ObjectGetter) (*pgxpool.Pool, string, auth.Lookup) {
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

	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}
	a := authz.New(pool)

	router := httpapi.NewRouter(pool, httpapi.RouterDeps{
		Queries:    q,
		Authorizer: a,
		Getter:     getter,
		Validate:   lookup.Validate,
		Load:       lookup.Load,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return pool, srv.URL, lookup
}

// castServerWithReviewer is castServer with a GrantReviewer wired in, exercising
// the additive grant-scoped review path in authorizeCast.
func castServerWithReviewer(t *testing.T, getter httpapi.ObjectGetter, reviewer httpapi.GrantReviewer) (*pgxpool.Pool, string, auth.Lookup) {
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

	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}
	a := authz.New(pool)

	router := httpapi.NewRouter(pool, httpapi.RouterDeps{
		Queries:       q,
		Authorizer:    a,
		Getter:        getter,
		GrantReviewer: reviewer,
		Validate:      lookup.Validate,
		Load:          lookup.Load,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return pool, srv.URL, lookup
}

// seedRealGrant builds the minimal folder→asset→role→request→grant chain so a
// grant with a real id exists (session_recordings.grant_id has an FK). subject is
// the grant's subject_user_id. Returns the grant id and the asset id.
func seedRealGrant(t *testing.T, pool *pgxpool.Pool, subject uuid.UUID) (grantID, assetID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)

	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "rev-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "a-" + uuid.NewString()[:8], Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "rev-role-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	req, err := q.CreateAccessRequest(ctx, sqlc.CreateAccessRequestParams{
		RequesterUserID: subject, RoleID: role.ID, AssetID: asset.ID,
		Reason: "review test", RequiredApprovals: 1, Status: "granted",
		RequestedDuration: pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
		GrantedDuration:   pgtype.Interval{Microseconds: int64(time.Hour / time.Microsecond), Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	grant, err := q.CreateAccessGrant(ctx, sqlc.CreateAccessGrantParams{
		RequestID: req.ID, RoleID: role.ID, ScopeAssetID: asset.ID,
		SubjectUserID: subject, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	return grant.ID, asset.ID
}

// seedGrantRecording inserts a recording attributed to grantID and returns its
// session ID.
func seedGrantRecording(t *testing.T, pool *pgxpool.Pool, userID, assetID, grantID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sessID := uuid.New()
	if err := sqlc.New(pool).UpsertSessionRecording(ctx, sqlc.UpsertSessionRecordingParams{
		SessionID: sessID,
		UserID:    userID,
		AssetID:   assetID,
		WorkerID:  "worker-test",
		Protocol:  "ssh",
		Format:    "asciicast",
		ObjectKey: fmt.Sprintf("recordings/%s.cast", sessID),
		SizeBytes: 42,
		Sha256:    "deadbeef",
		Status:    "completed",
		GrantID:   pgtype.UUID{Bytes: grantID, Valid: true},
	}); err != nil {
		t.Fatalf("upsert grant recording: %v", err)
	}
	return sessID
}

// seedUserWithCap creates a user + a global role carrying recording:read and
// binds it to the user. Returns the user's ID and a valid auth token.
func seedUserWithCap(t *testing.T, pool *pgxpool.Pool, lookup auth.Lookup, email string, withCap bool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)

	u, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := auth.HashPassword("testpw")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}

	if withCap {
		// Create a global role with recording:read and bind it to this user.
		role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
			Name: "rec-reader-" + u.ID.String()[:8],
		})
		if err != nil {
			t.Fatalf("create role: %v", err)
		}
		sc, ac, qu := authz.NormalizeCap("recording:read")
		if err := q.InsertRoleCapability(ctx, sqlc.InsertRoleCapabilityParams{
			RoleID: role.ID, Scope: sc, Action: ac, Qualifier: qu,
		}); err != nil {
			t.Fatalf("insert role capability: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID:        role.ID,
			SubjectUserID: pgtype.UUID{Bytes: u.ID, Valid: true},
		}); err != nil {
			t.Fatalf("bind role: %v", err)
		}
	}

	tok, err := lookup.Tokens.Issue(ctx, u.ID, 60*1_000_000_000 /* 1 minute */)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return u.ID, tok
}

// seedRecording inserts a session_recordings row and returns the session ID.
func seedRecording(t *testing.T, pool *pgxpool.Pool, userID, assetID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sessID := uuid.New()
	key := fmt.Sprintf("recordings/%s.cast", sessID)
	if err := sqlc.New(pool).UpsertSessionRecording(ctx, sqlc.UpsertSessionRecordingParams{
		SessionID: sessID,
		UserID:    userID,
		AssetID:   assetID,
		WorkerID:  "worker-test",
		Protocol:  "ssh",
		Format:    "asciicast",
		ObjectKey: key,
		SizeBytes: 42,
		Sha256:    "deadbeef",
		Status:    "completed",
	}); err != nil {
		t.Fatalf("upsert recording: %v", err)
	}
	return sessID
}

// doGet issues a GET request optionally with a Bearer token and/or
// Sec-Fetch-Site header (to simulate same-origin browser requests with cookie).
func doGet(t *testing.T, url, token, secFetchSite string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if secFetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", secFetchSite)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// doHead issues a HEAD request optionally with a Bearer token and/or
// Sec-Fetch-Site header.
func doHead(t *testing.T, url, token, secFetchSite string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if secFetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", secFetchSite)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// doGetCookie issues a GET request carrying the token in the jumpgate_session
// cookie (browser path) rather than the Authorization header, optionally with a
// Sec-Fetch-Site header to exercise the CSRF gate.
func doGetCookie(t *testing.T, url, token, secFetchSite string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Cookie", auth.SessionCookie+"="+token)
	}
	if secFetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", secFetchSite)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestCastNoAuth: no token → 401.
func TestCastNoAuth(t *testing.T) {
	getter := &fakeObjectGetter{body: `{"version":2}`}
	_, srvURL, _ := castServer(t, getter)
	sessID := uuid.New()
	resp := doGet(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", "", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", resp.StatusCode)
	}
}

// TestCastValidTokenWithCap: authorized user + existing recording → 200 + body.
func TestCastValidTokenWithCap(t *testing.T) {
	const castBody = `{"version":2,"width":80,"height":24}` + "\n" + `[0.5,"o","hello"]`
	getter := &fakeObjectGetter{body: castBody}
	pool, srvURL, lookup := castServer(t, getter)

	assetID := uuid.New()
	userID, tok := seedUserWithCap(t, pool, lookup, "alice@test", true)
	sessID := seedRecording(t, pool, userID, assetID)

	resp := doGet(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", tok, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200, got %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "asciicast") {
		t.Errorf("Content-Type = %q, want application/x-asciicast", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello") {
		t.Errorf("body missing expected content: %q", string(body))
	}
}

// TestCastNoCapOrMissingRecording: a user without recording:read OR a
// non-existent session ID → 404 (existence-hiding).
func TestCastNoCapOrMissingRecording(t *testing.T) {
	getter := &fakeObjectGetter{body: "x"}
	pool, srvURL, lookup := castServer(t, getter)

	_, noCap := seedUserWithCap(t, pool, lookup, "bob@test", false)

	// (a) valid token, no recording:read, random session ID → 404
	resp := doGet(t, srvURL+"/api/recordings/"+uuid.New().String()+"/cast", noCap, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("(no cap) want 404, got %d", resp.StatusCode)
	}

	// (b) totally unknown session ID, no token → 401 (auth before existence check)
	resp2 := doGet(t, srvURL+"/api/recordings/"+uuid.New().String()+"/cast", "", "")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("(no token, unknown id) want 401, got %d", resp2.StatusCode)
	}
}

// TestCastHeadAuthorized: authorized user + existing recording, HEAD probe →
// 200, asciicast Content-Type, and NO body. Same status as the GET path so the
// player's HEAD probe faithfully predicts a streamable recording.
func TestCastHeadAuthorized(t *testing.T) {
	getter := &fakeObjectGetter{body: `{"version":2}` + "\n" + `[0.5,"o","hi"]`}
	pool, srvURL, lookup := castServer(t, getter)

	assetID := uuid.New()
	userID, tok := seedUserWithCap(t, pool, lookup, "carol@test", true)
	sessID := seedRecording(t, pool, userID, assetID)

	resp := doHead(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", tok, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 for authorized HEAD, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "asciicast") {
		t.Errorf("Content-Type = %q, want application/x-asciicast", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD response must have no body, got %d bytes: %q", len(body), body)
	}
}

// TestCastHeadUnauthorizedOrMissing: HEAD mirrors GET's existence-hiding —
// a user without recording:read (or a missing recording) → 404.
func TestCastHeadUnauthorizedOrMissing(t *testing.T) {
	getter := &fakeObjectGetter{body: "x"}
	pool, srvURL, lookup := castServer(t, getter)

	_, noCap := seedUserWithCap(t, pool, lookup, "dave@test", false)

	// (a) valid token, no recording:read, random session ID → 404
	resp := doHead(t, srvURL+"/api/recordings/"+uuid.New().String()+"/cast", noCap, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("(no cap) want 404 for HEAD, got %d", resp.StatusCode)
	}

	// (b) no token → 401 (auth before existence check), same as GET.
	resp2 := doHead(t, srvURL+"/api/recordings/"+uuid.New().String()+"/cast", "", "")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("(no token) want 401 for HEAD, got %d", resp2.StatusCode)
	}
}

// TestCastCookieSameOrigin: a browser-style request carrying the token in the
// jumpgate_session cookie with Sec-Fetch-Site: same-origin → 200 (exercises the
// cookie CSRF gate, which the Bearer-only tests don't cover).
func TestCastCookieSameOrigin(t *testing.T) {
	const castBody = `{"version":2}` + "\n" + `[0.5,"o","cookie-hello"]`
	getter := &fakeObjectGetter{body: castBody}
	pool, srvURL, lookup := castServer(t, getter)

	assetID := uuid.New()
	userID, tok := seedUserWithCap(t, pool, lookup, "erin@test", true)
	sessID := seedRecording(t, pool, userID, assetID)

	resp := doGetCookie(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", tok, "same-origin")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200 for same-origin cookie GET, got %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "cookie-hello") {
		t.Errorf("body missing expected content: %q", string(body))
	}
}

// TestCastGrantReviewer: a caller WITHOUT recording:read can stream a
// grant-attributed recording when the GrantReviewer authorizes them (subject or
// potential approver), but is still denied (404) on an unattributed (NULL
// grant_id) recording — the grant-review path only adds access.
func TestCastGrantReviewer(t *testing.T) {
	const castBody = `{"version":2}` + "\n" + `[0.5,"o","review-hello"]`
	getter := &fakeObjectGetter{body: castBody}

	rev := &fakeGrantReviewer{allow: map[[2]uuid.UUID]bool{}}
	pool, srvURL, lookup := castServerWithReviewer(t, getter, rev)

	// Caller holds NO recording:read.
	userID, tok := seedUserWithCap(t, pool, lookup, "reviewer@test", false)

	// A real access_grant (grant_id has an FK) with its asset.
	grantID, assetID := seedRealGrant(t, pool, userID)
	rev.allow[[2]uuid.UUID{userID, grantID}] = true

	grantSess := seedGrantRecording(t, pool, userID, assetID, grantID)
	nullSess := seedRecording(t, pool, userID, assetID)

	// (a) grant-attributed recording, reviewer authorizes → 200 + body.
	resp := doGet(t, srvURL+"/api/recordings/"+grantSess.String()+"/cast", tok, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("(grant reviewer) want 200, got %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "review-hello") {
		t.Errorf("body missing expected content: %q", string(body))
	}

	// (b) NULL-grant recording, same caller (no recording:read) → 404, since the
	//     grant-review path does not apply to unattributed recordings.
	resp2 := doGet(t, srvURL+"/api/recordings/"+nullSess.String()+"/cast", tok, "")
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("(NULL grant, no cap) want 404, got %d", resp2.StatusCode)
	}
}

// TestCastCookieMissingSecFetch: the same cookie WITHOUT Sec-Fetch-Site is
// blocked by the fail-closed CSRF gate — no user is attached, so the handler
// returns 401.
func TestCastCookieMissingSecFetch(t *testing.T) {
	getter := &fakeObjectGetter{body: `{"version":2}`}
	pool, srvURL, lookup := castServer(t, getter)

	assetID := uuid.New()
	userID, tok := seedUserWithCap(t, pool, lookup, "frank@test", true)
	sessID := seedRecording(t, pool, userID, assetID)

	resp := doGetCookie(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", tok, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 for cookie without Sec-Fetch-Site (CSRF gate), got %d", resp.StatusCode)
	}
}
