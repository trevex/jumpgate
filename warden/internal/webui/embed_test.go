//go:build embedui

package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbed(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(200)
	})
	h := Handler(next)

	t.Run("GET / returns index.html", func(t *testing.T) {
		nextCalled = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if nextCalled {
			t.Fatal("expected SPA handler, got next")
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("expected text/html, got %q", ct)
		}
		if body := rec.Body.String(); !strings.Contains(body, "jumpgate") {
			t.Fatalf("index.html not served: %q", body)
		}
	})

	t.Run("GET /healthz delegates to next", func(t *testing.T) {
		nextCalled = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		if !nextCalled {
			t.Fatal("expected delegation to next for /healthz")
		}
	})

	t.Run("GET /jumpgate.x/y delegates to next", func(t *testing.T) {
		nextCalled = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/jumpgate.identity.v1/SomeRpc", nil))
		if !nextCalled {
			t.Fatal("expected delegation to next for RPC path")
		}
	})

	t.Run("POST / delegates to next", func(t *testing.T) {
		nextCalled = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
		if !nextCalled {
			t.Fatal("expected delegation to next for non-GET")
		}
	})
}
