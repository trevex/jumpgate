package webcors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSAllowlisted(t *testing.T) {
	h := New([]string{"http://localhost:5173"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest("OPTIONS", "/x", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 || rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight code=%d hdrs=%v", rec.Code, rec.Header())
	}
	req2 := httptest.NewRequest("POST", "/x", nil)
	req2.Header.Set("Origin", "http://evil.example")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("evil origin allowed")
	}
}

func TestCORSDisabledPassthrough(t *testing.T) {
	called := false
	h := New(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(200) }))
	req := httptest.NewRequest("OPTIONS", "/x", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("empty allowlist must pass through")
	}
}
