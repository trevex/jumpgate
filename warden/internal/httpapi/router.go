// Package httpapi builds the control-plane HTTP surface. It serves the
// health endpoint (DB-aware) and the recording cast proxy.
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Pinger is the subset of the DB pool the health check needs.
type Pinger interface {
	Ping(ctx context.Context) error
}

// NewRouter returns the control-plane HTTP handler. db may be nil (health then
// reports process liveness only). deps is optional; pass RouterDeps{} to skip
// the recording cast proxy.
func NewRouter(db Pinger, deps ...RouterDeps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		status := "ok"
		code := http.StatusOK
		if db != nil {
			ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
			defer cancel()
			if err := db.Ping(ctx); err != nil {
				status = "degraded"
				code = http.StatusServiceUnavailable
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})

	// Recording cast proxy: streams asciicast objects server-side so the browser
	// never needs a presigned URL. Only mounted when deps are provided.
	if len(deps) > 0 {
		d := deps[0]
		if d.Validate != nil && d.Load != nil {
			authMw := CookieAuth(d.Validate, d.Load)
			r.With(authMw).Get("/api/recordings/{sessionId}/cast", castHandler(d.Queries, d.Authorizer, d.Getter))
		}
	}

	return r
}
