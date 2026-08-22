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
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// ObjectGetter streams a recording object body from the object store.
// Satisfied by *recording.S3Presigner in production; a fake in tests.
type ObjectGetter interface {
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
}

// castHandler returns a chi handler that cookie-authenticates, authorizes
// recording:read on the recording's asset scope, and streams the asciicast
// object body to the caller. It applies existence-hiding: any auth or
// not-found condition returns 404 so that denied callers cannot enumerate
// recording IDs.
func castHandler(q *gen.Queries, a authz.Authorizer, getter ObjectGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Authentication: user must be present (attached by CookieAuth middleware).
		caller, ok := auth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		// 2. Parse session ID.
		rawID := chi.URLParam(r, "sessionId")
		sessionID, err := uuid.Parse(rawID)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// 3. Load the recording row — existence-hiding: treat DB not-found as 404.
		row, err := q.GetSessionRecording(r.Context(), sessionID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// 4. Authorization: mirror GetRecordingDownload — require recording:read on
		//    the recording's asset scope. Deny → 404 (existence-hiding, same as
		//    catalog topology).
		caps, err := a.CapabilitiesOnScope(r.Context(), caller.ID, authz.AssetScope(row.AssetID))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !caps.Allows("recording:read") {
			http.NotFound(w, r)
			return
		}

		// 5. Object getter must be configured; if not, the route is unavailable.
		if getter == nil {
			http.Error(w, "recording retrieval not configured", http.StatusServiceUnavailable)
			return
		}

		// 6. Stream the object.
		body, err := getter.GetObject(r.Context(), row.ObjectKey)
		if err != nil {
			// Object missing or unreachable → 404 (existence-hiding).
			http.NotFound(w, r)
			return
		}
		defer body.Close()

		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = io.Copy(w, body)
	}
}

// RouterDeps holds the optional dependencies that the recording cast proxy
// requires. All fields may be nil; absent deps cause the cast route to fail
// closed with an appropriate status code.
type RouterDeps struct {
	// Queries is used to load recording metadata. If nil, the cast route
	// returns 503.
	Queries *gen.Queries
	// Authorizer checks the caller's recording:read capability. If nil, the
	// cast route returns 503.
	Authorizer authz.Authorizer
	// Getter streams asciicast objects from the object store. If nil, the cast
	// route returns 503 (recording retrieval not configured).
	Getter ObjectGetter
	// Validate resolves a raw token to a user ID (TokenService.Validate).
	Validate func(context.Context, string) (uuid.UUID, error)
	// Load hydrates a CurrentUser from its ID (auth.Lookup.Load).
	Load func(context.Context, uuid.UUID) (auth.CurrentUser, error)
}
