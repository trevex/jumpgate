package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// ObjectGetter streams a recording object body from the object store.
// Satisfied by *recording.S3Presigner in production; a fake in tests.
type ObjectGetter interface {
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	// HeadObject verifies the object exists and the store is reachable without
	// transferring the body. The HEAD handler uses it so its result faithfully
	// predicts the GET outcome (same object-missing / store-unreachable → 404).
	HeadObject(ctx context.Context, key string) error
}

// GrantReviewer authorizes grant-scoped recording review: a recording attributed
// to a grant is viewable by the grant's subject or a potential approver of the
// grant's originating request. Additive to the recording:read capability — the
// cast prelude consults it only after the cap check denies, and only for
// grant-attributed recordings. Backed by *accessrequest.Service. Nil disables the
// additive path (only recording:read applies). Fails closed.
type GrantReviewer interface {
	CanReviewGrant(ctx context.Context, caller, grantID uuid.UUID) (bool, error)
}

// authorizeCast runs the shared prelude for both the GET and HEAD cast
// handlers: it authenticates the caller, parses and loads the recording row,
// and checks the recording:read capability on the recording's asset scope. It
// applies existence-hiding: any auth or not-found condition returns 404 so that
// denied callers cannot enumerate recording IDs. On any failure it writes the
// error response and returns ok=false; on success it returns the row and ok=true.
func (d RouterDeps) authorizeCast(w http.ResponseWriter, r *http.Request) (sqlc.SessionRecording, bool) {
	// 0. Defense-in-depth: required deps must be wired. Don't rely on the
	//    Recoverer catching a nil-deref → 500; fail closed with 503.
	if d.Queries == nil || d.Authorizer == nil {
		http.Error(w, "recording retrieval not configured", http.StatusServiceUnavailable)
		return sqlc.SessionRecording{}, false
	}

	// 1. Authentication: user must be present (attached by CookieAuth middleware).
	caller, ok := auth.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return sqlc.SessionRecording{}, false
	}

	// 2. Parse session ID.
	rawID := chi.URLParam(r, "sessionId")
	sessionID, err := uuid.Parse(rawID)
	if err != nil {
		http.NotFound(w, r)
		return sqlc.SessionRecording{}, false
	}

	// 3. Load the recording row — existence-hiding: treat DB not-found as 404.
	row, err := d.Queries.GetSessionRecording(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return sqlc.SessionRecording{}, false
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return sqlc.SessionRecording{}, false
	}

	// 4. Authorization: mirror GetRecordingDownload — require recording:read on
	//    the recording's asset scope. Deny → 404 (existence-hiding, same as
	//    catalog topology).
	caps, err := d.Authorizer.CapabilitiesOnScope(r.Context(), caller.ID, authz.AssetScope(row.AssetID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return sqlc.SessionRecording{}, false
	}
	if !caps.Allows(authz.RecordingReadCap) {
		// Additive grant-scoped review: a grant-attributed recording is viewable
		// by the grant's subject or a potential approver, even without
		// recording:read. Strictly additive — an unattributed (NULL grant_id)
		// recording still requires recording:read. Deny stays 404 (existence-hiding).
		if !row.GrantID.Valid || d.GrantReviewer == nil {
			http.NotFound(w, r)
			return sqlc.SessionRecording{}, false
		}
		reviewable, err := d.GrantReviewer.CanReviewGrant(r.Context(), caller.ID, uuid.UUID(row.GrantID.Bytes))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return sqlc.SessionRecording{}, false
		}
		if !reviewable {
			http.NotFound(w, r)
			return sqlc.SessionRecording{}, false
		}
	}

	return row, true
}

// castHandler returns a chi handler that cookie-authenticates, authorizes
// recording:read on the recording's asset scope, and streams the asciicast
// object body to the caller.
func castHandler(d RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row, ok := d.authorizeCast(w, r)
		if !ok {
			return
		}

		// Object getter must be configured; if not, the route is unavailable.
		if d.Getter == nil {
			http.Error(w, "recording retrieval not configured", http.StatusServiceUnavailable)
			return
		}

		// Stream the object.
		body, err := d.Getter.GetObject(r.Context(), row.ObjectKey)
		if err != nil {
			// Object missing or unreachable → 404 (existence-hiding).
			http.NotFound(w, r)
			return
		}
		defer func() { _ = body.Close() }()

		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = io.Copy(w, body)
	}
}

// castHeadHandler returns a chi handler for HEAD probes against the cast route.
// It runs the same authorization prelude AND the same object fetch (metadata
// only, via HeadObject) as the GET handler, so it returns the same 401/404/503
// status codes — making the frontend player's HEAD probe a faithful predictor of
// the GET outcome. It writes no body; on success it sets the asciicast
// Content-Type and returns 200.
func castHeadHandler(d RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row, ok := d.authorizeCast(w, r)
		if !ok {
			return
		}
		if d.Getter == nil {
			http.Error(w, "recording retrieval not configured", http.StatusServiceUnavailable)
			return
		}
		// Mirror GET: a missing object or unreachable store must 404 here too, not
		// a misleading 200 that lets the player mount and then fail on the body GET.
		if err := d.Getter.HeadObject(r.Context(), row.ObjectKey); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
	}
}

// RouterDeps holds the optional dependencies that the recording cast proxy
// requires. All fields may be nil; absent deps cause the cast route to fail
// closed with an appropriate status code.
type RouterDeps struct {
	// Queries is used to load recording metadata. If nil, the cast route
	// returns 503.
	Queries *sqlc.Queries
	// Authorizer checks the caller's recording:read capability. If nil, the
	// cast route returns 503.
	Authorizer *authz.Authorizer
	// Getter streams asciicast objects from the object store. If nil, the cast
	// route returns 503 (recording retrieval not configured).
	Getter ObjectGetter
	// GrantReviewer authorizes grant-scoped review of a grant-attributed
	// recording (subject or potential approver), additive to recording:read. If
	// nil, only the recording:read gate applies.
	GrantReviewer GrantReviewer
	// Validate resolves a raw token to a user ID (TokenService.Validate).
	Validate func(context.Context, string) (uuid.UUID, error)
	// Load hydrates a CurrentUser from its ID (auth.Lookup.Load).
	Load func(context.Context, uuid.UUID) (auth.CurrentUser, error)
}
