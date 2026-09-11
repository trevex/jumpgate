package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSOCallbackHandler_Code(t *testing.T) {
	resultCh := make(chan ssoResult, 1)
	srv := httptest.NewServer(ssoCallbackHandler(resultCh))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/callback?code=abc")
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	select {
	case res := <-resultCh:
		if res.code != "abc" {
			t.Errorf("code = %q, want %q", res.code, "abc")
		}
		if res.err != "" {
			t.Errorf("err = %q, want empty", res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSSOCallbackHandler_Error(t *testing.T) {
	resultCh := make(chan ssoResult, 1)
	srv := httptest.NewServer(ssoCallbackHandler(resultCh))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/callback?error=access_denied")
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	select {
	case res := <-resultCh:
		if res.err != "access_denied" {
			t.Errorf("err = %q, want %q", res.err, "access_denied")
		}
		if res.code != "" {
			t.Errorf("code = %q, want empty", res.code)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result")
	}
}

func TestExchangeCLICode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/oidc/cli/exchange" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		if body.Code != "abc" {
			t.Errorf("posted code = %q, want %q", body.Code, "abc")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "t"})
	}))
	defer srv.Close()

	token, err := exchangeCLICode(srv.Client(), srv.URL, "abc")
	if err != nil {
		t.Fatalf("exchangeCLICode: %v", err)
	}
	if token != "t" {
		t.Errorf("token = %q, want %q", token, "t")
	}
}

func TestExchangeCLICode_BadCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid code", http.StatusBadRequest)
	}))
	defer srv.Close()

	if _, err := exchangeCLICode(srv.Client(), srv.URL, "bad"); err == nil {
		t.Fatal("expected an error for a rejected code")
	}
}

func TestRunLogin_SSOExclusiveWithEmail(t *testing.T) {
	loginSSO = true
	loginEmail = "user@example.com"
	loginPassword = ""
	defer func() {
		loginSSO = false
		loginEmail = ""
	}()

	if err := runLogin(loginCmd, nil); err == nil {
		t.Fatal("expected an error when --sso is combined with --email")
	}
}

func TestRunLogin_SSOExclusiveWithPassword(t *testing.T) {
	loginSSO = true
	loginEmail = ""
	loginPassword = "hunter2"
	defer func() {
		loginSSO = false
		loginPassword = ""
	}()

	if err := runLogin(loginCmd, nil); err == nil {
		t.Fatal("expected an error when --sso is combined with --password")
	}
}
