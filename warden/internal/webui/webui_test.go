//go:build !embedui

package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerPassthroughDefault(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) })
	rec := httptest.NewRecorder()
	Handler(next).ServeHTTP(rec, httptest.NewRequest("GET", "/anything", nil))
	if !called || rec.Code != 204 {
		t.Fatalf("default build must pass through: called=%v code=%d", called, rec.Code)
	}
}
