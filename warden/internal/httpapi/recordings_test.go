package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
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

	q := gen.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}
	a := authz.NewSQLAuthorizer(pool)

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

// seedUserWithCap creates a user + a global role carrying recording:read and
// binds it to the user. Returns the user's ID and a valid auth token.
func seedUserWithCap(t *testing.T, pool *pgxpool.Pool, lookup auth.Lookup, email string, withCap bool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	u, err := q.CreateUserFull(ctx, gen.CreateUserFullParams{Email: email, DisplayName: email})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := auth.HashPassword("testpw")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserPassword(ctx, gen.SetUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}

	if withCap {
		// Create a global role with recording:read and bind it to this user.
		capsJSON := []byte(`["recording:read"]`)
		role, err := q.CreateRole(ctx, gen.CreateRoleParams{
			Name:         "rec-reader-" + u.ID.String()[:8],
			Capabilities: capsJSON,
		})
		if err != nil {
			t.Fatalf("create role: %v", err)
		}
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
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
	if err := gen.New(pool).UpsertSessionRecording(ctx, gen.UpsertSessionRecordingParams{
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

// ─── tests ────────────────────────────────────────────────────────────────────

// TestCastNoAuth: no token → 401.
func TestCastNoAuth(t *testing.T) {
	getter := &fakeObjectGetter{body: `{"version":2}`}
	_, srvURL, _ := castServer(t, getter)
	sessID := uuid.New()
	resp := doGet(t, srvURL+"/api/recordings/"+sessID.String()+"/cast", "", "")
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("(no cap) want 404, got %d", resp.StatusCode)
	}

	// (b) totally unknown session ID, no token → 401 (auth before existence check)
	resp2 := doGet(t, srvURL+"/api/recordings/"+uuid.New().String()+"/cast", "", "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("(no token, unknown id) want 401, got %d", resp2.StatusCode)
	}
}
